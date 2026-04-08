document.addEventListener("DOMContentLoaded", () => {
  const status = document.querySelector("[data-status]");
  if (status) {
    status.textContent = "Starter scaffold loaded.";
  }
});

