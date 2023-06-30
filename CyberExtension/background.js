chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (request.action === "checkLink") {
    const url = request.url; // Récupère l'URL à vérifier depuis la requête
    const apiKey = "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f"; 
    fetch("https://www.virustotal.com/vtapi/v2/url/report", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `resource=${encodeURIComponent(url)}&apikey=${apiKey}`, // Prépare les données a envoyer à VirusTotal pour la vérification de l'URL
    })
      .then((response) => response.json()) // Convertit la réponse en JSON
      .then((data) => {
        sendResponse({ result: data }); // Envoie la réponse contenant les données de résultat à l'extension
      })
      .catch((error) => {
        console.error(error);
        sendResponse({ error: "Une erreur s'est produite lors de la vérification du lien." }); // En cas d'erreur, envoie une réponse d'erreur à l'extension
      });

    return true; // Indique à Chrome que l'extension attend une réponse 
  }
});
