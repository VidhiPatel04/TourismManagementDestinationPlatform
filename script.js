document.addEventListener("DOMContentLoaded", function () {
    const reviews = document.querySelectorAll(".review .stars");

    reviews.forEach(starBlock => {
        let stars = starBlock.textContent.trim();
        let starHTML = "";

        for (let i = 0; i < 5; i++) {
            if (i < stars.length) {
                starHTML += "⭐"; // Filled Star
            } else {
                starHTML += "☆"; // Empty Star
            }
        }

        starBlock.innerHTML = starHTML;
    });
});
document.addEventListener("DOMContentLoaded", () => {
    const destinations = document.querySelectorAll(".destination");
    const destinationSelect = document.getElementById("destination");

    destinations.forEach(destination => {
        destination.addEventListener("click", () => {
            // Remove blue background from all destinations
            destinations.forEach(dest => dest.classList.remove("selected"));

            // Add blue background to clicked destination
            destination.classList.add("selected");

            // Get the destination name from the paragraph inside the div
            const destinationName = destination.querySelector("p").textContent;

            // Update the select dropdown
            for (let option of destinationSelect.options) {
                if (option.textContent.includes(destinationName)) {
                    option.selected = true;
                    break;
                }
            }
        });
    });
});