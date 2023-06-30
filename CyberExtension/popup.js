// Lorsque le bouton de vérification est cliqué
document.getElementById("checkButton").addEventListener("click", function () {
  // Récupère l'URL à vérifier depuis l'entrée de texte
  const url = document.getElementById("linkInput").value;

  // Envoie un message à l'extension avec l'action "checkLink" et l'URL à vérifier
  chrome.runtime.sendMessage({ action: "checkLink", url }, function (response) {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
      displayError("Une erreur s'est produite lors de la communication avec l'extension.");
    } else if (response.error) {
      // En cas d'erreur dans la réponse
      displayError(response.error);
    } else {
      // En cas de réponse réussie
      displayResults(response.result);
    }
  });
});


// Affiche les résultats de la vérification d'URL
function displayResults(result) {
  const resultElement = document.getElementById("result");
  resultElement.innerHTML = "";

  if (result.response_code === 1) {
    // Si le code de réponse est 1, le lien est considéré comme sécurisé par VirusTotal
    resultElement.innerHTML += "<p>Le lien est securise selon VirusTotal.</p>";
  } else if (result.response_code === -2) {
    // Si le code de réponse est -2, le lien n'a pas encore été analysé par VirusTotal
    resultElement.innerHTML += "<p>Le lien n'a pas encore ete analyse par VirusTotal.</p>";
  } else {
    // Dans tous les autres cas, le lien est considéré comme non sécurisé par VirusTotal
    resultElement.innerHTML += "<p>Le lien est considere comme non securise selon VirusTotal.</p>";
  }

  if (result.positives > 0) {
    // Si des antivirus ont détecté des problèmes avec le lien
    resultElement.innerHTML += `<p>Antivirus positifs : ${result.positives} / ${result.total}</p>`;
    const antivirusList = document.createElement("ul");
    for (const scanner in result.scans) {
      if (result.scans[scanner].detected) {
        // Pour chaque antivirus qui a détecté un problème, affiche les détails
        const listItem = document.createElement("li");
        listItem.innerText = `${scanner}: ${result.scans[scanner].result}`;
        antivirusList.appendChild(listItem);
      }
    }
    resultElement.appendChild(antivirusList);
  }
}

// Affiche une erreur dans l'élément de résultat
function displayError(error) {
  const resultElement = document.getElementById("result");
  resultElement.innerHTML = `<p class="error">${error}</p>`;
}
