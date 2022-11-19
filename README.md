# WordPress-Security

Sucuri and Wordfence are 2 security plugins. I have used them on many clients' websites. They provide the best features to secure the WordPress site from intrusions. 

But sometimes they cannot remove all the malware or backdoors from your website. The following steps can be taken to ensure everything is secure and all the malware is removed from the WP Core, Plugins, Themes and Database.


Scan your website with webpagetest.org and analyze the results. 

Integrity check of your core WordPress files.

Check for recently modified files.

Use diagnostic tools provided by Google, Bing, Norton etc.

Remove the malware by using comparison tools like WinMerge. 

Remove hidden backdoors.

Change passwords and generate new secret keys.

isolating your website from cross-contamination, restricting IPs and setting up the CAPTCHA to deter automated attacks.

Create website backups.

Use a website firewall.

Look for obfuscated code in your files. 

check your website on VirusTotal.

Look for common malicious PHP functions, such as eval, base64_decode, gzinflate, preg_replace, str_replace, etc in your database by analyzing SQL. 

Often backdoors are embedded in files named similar to WordPress core files but located in the wrong directories.

It is critical that all backdoors are closed to successfully stop a WordPress hack, otherwise your site will be reinfected quickly.
