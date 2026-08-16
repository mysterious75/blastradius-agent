const params = new URLSearchParams(window.location.search);
document.getElementById("out").innerHTML = params.get("name");
