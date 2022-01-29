package pages

/*
IndexPage renders the html content for the index page.
*/
const IndexPage = `
<html>
	<head>
		<title>OAuth-2 Test</title>
	</head>
	<body>
		<h2>OAuth-2 Test</h2>
		<p>
			Login with the following,
		</p>
		<ul>
			<li><a href="/login-ms">Login</a></li>
			<li><a href="/protected-ms">Access the Secure Area!</a></li>
		</ul>
	</body>
</html>
`

const CallBackHeaderPage = `
<html>
	<head>
		<style>
         pre {
            overflow-x: auto;
            white-space: pre-wrap;
            white-space: -moz-pre-wrap;
            white-space: -pre-wrap;
            white-space: -o-pre-wrap;
            word-wrap: break-word;
         }
      	</style>
		<title>OAuth-2 Test</title>
	</head>
	<body>
		<h2>OAuth-2 Test Token Response</h2>
		<pre>
			<code>
`

const CallBackFooterPage = `
			</code>
		</pre>
		<ul>
			<li><a href="/protected-ms">Access the Secure Area!</a></li>
		</ul>
	</body>
</html>
`
const UnAuthorizedPage = `
<html>
	<head>
		<title>OAuth-2 Test</title>
	</head>
	<body>
		<h2>OAuth-2 Test</h2>
		<p>
			You shall not PASS!
		</p>
		<ul>
			<li><a href="/login-ms">Login</a></li>
		</ul>
	</body>
</html>
`

const SecureArea = `
<html>
	<head>
		<title>OAuth-2 Test</title>
	</head>
	<body>
		<h2>OAuth-2 Test</h2>
		<p>
			Welcome to the VIP Area!
		</p>
		<ul>
			<li><a href="/logout-ms">Logout</a></li>
		</ul>
	</body>
</html>
`
