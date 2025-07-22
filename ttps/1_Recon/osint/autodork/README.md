## Examples
Small warning here: if you don't use **-cat** SiteDorks will open a lot of tabs in your browser and probably will make Google throw you a CAPTCHA. Increase waiting time with option '-wait' to decrease the chance of getting a CAPTCHA.

Want to look for "uber.com" with different sites containing all kinds of content using Google? Use the following command:
```
podman exec dork sitedorks -query '"uber.com"'
```
Want to look for "uber website" (with quotes and spaces in the query)? Use the following command:
```
podman exec dork sitedorks -query '"uber website"'
```
Want to search for communication invites with Yandex but leave site: out of the query? Just use the following command:
```
podman exec dork sitedorks -cat comm -site disable -engine yandex -query uber
```
And if you  want to see which categories are on file, for example:
```
podman exec dork sitedorks -file sitedorks.csv -cats
```

For searching in Dutch (para)medical websites, use the following command:
```
podman exec dork sitedorks -cat medi -file sitedorks-nl.csv -query somekeyword
```

# Google Dorks
Don't know what to look for? 
Try:
* https://twitter.com/search?q=%23googledork%20OR%20%23googledorks
* https://gbhackers.com/latest-google-dorks-list
* https://www.dorksearch.com


