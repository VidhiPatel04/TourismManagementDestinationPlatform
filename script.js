document.addEventListener("DOMContentLoaded", function () {
    // Star Rating Display
    const reviews = document.querySelectorAll(".review .stars");
    reviews.forEach(starBlock => {
        let stars = starBlock.textContent.trim().length; // Count the number of ★ characters
        let starHTML = "";

        for (let i = 0; i < 5; i++) {
            starHTML += (i < stars) ? "⭐" : "☆"; // Filled or empty star
        }

        starBlock.innerHTML = starHTML;
    });

    // Destination Selection
    const destinations = document.querySelectorAll(".destination");
    const destinationSelect = document.getElementById("destination");

    destinations.forEach(destination => {
        destination.addEventListener("click", () => {
            destinations.forEach(dest => dest.classList.remove("selected"));
            destination.classList.add("selected");
            const destinationName = destination.getAttribute("data-destination");
            console.log("Selected destination:", destinationName);

            for (let option of destinationSelect.options) {
                if (option.value === destinationName) {
                    option.selected = true;
                    break;
                }
            }
        });
    });

    // Destination Details Data
    const destinationDetails = {
        Paris: {
            image: "./images/destination1.jpeg",
            description: "Paris, the capital of France, is a city renowned for its art, culture, and history. Often called the City of Lights, it’s home to iconic landmarks like the Eiffel Tower, Notre-Dame Cathedral, and the Louvre Museum, which houses the Mona Lisa. Stroll along the Champs-Élysées, enjoy a croissant at a quaint café, or take a romantic boat ride on the Seine River.",
            highlights: [
                "Visit the Eiffel Tower for panoramic views of the city.",
                "Explore the Louvre Museum and see the Mona Lisa.",
                "Enjoy a Seine River cruise at sunset.",
                "Discover the historic Notre-Dame Cathedral."
            ]
        },
        Bali: {
            image: "./images/destination2.jpeg",
            description: "Bali, an Indonesian island, is a tropical paradise known for its lush landscapes, sandy beaches, and vibrant culture. From the rice terraces of Ubud to the surf-friendly waves of Kuta, Bali offers a mix of relaxation and adventure. Immerse yourself in Balinese traditions, visit ancient temples, and indulge in local cuisine.",
            highlights: [
                "Relax on the beaches of Kuta and Seminyak.",
                "Visit the Tegalalang Rice Terraces in Ubud.",
                "Explore the sacred Monkey Forest Sanctuary.",
                "Experience a traditional Balinese dance performance."
            ]
        },
        Tokyo: {
            image: "./images/destination3.jpeg",
            description: "Tokyo, Japan’s bustling capital, seamlessly blends the ultramodern with the traditional. Skyscrapers and neon lights coexist with historic temples and serene gardens. Dive into the vibrant neighborhoods of Shibuya and Shinjuku, savor sushi at Tsukiji Market, or visit the Imperial Palace for a glimpse of Japan’s imperial history.",
            highlights: [
                "Cross the famous Shibuya Crossing.",
                "Visit Senso-ji Temple, Tokyo’s oldest temple.",
                "Explore the anime and manga culture in Akihabara.",
                "Enjoy sushi at Tsukiji Outer Market."
            ]
        },
        "New York": {
            image: "./images/destination4.jpeg",
            description: "New York City, often called the Big Apple, is a global hub for culture, finance, and entertainment. From the bright lights of Times Square to the tranquility of Central Park, NYC offers endless experiences. Catch a Broadway show, visit the Statue of Liberty, or explore world-class museums like the Met.",
            highlights: [
                "See the Statue of Liberty and Ellis Island.",
                "Walk through Central Park and visit the zoo.",
                "Catch a Broadway show in the Theater District.",
                "Visit the Metropolitan Museum of Art."
            ]
        },
        Banff: {
            image: "./images/destination5.jpeg",
            description: "Banff, located in Canada’s Rocky Mountains, is a haven for nature lovers. Surrounded by stunning peaks, turquoise lakes, and abundant wildlife, Banff National Park offers year-round outdoor activities. Ski in the winter, hike in the summer, and soak in the Banff Upper Hot Springs for a relaxing experience.",
            highlights: [
                "Hike to Lake Louise and Moraine Lake.",
                "Ski or snowboard at Banff Sunshine Village.",
                "Relax in the Banff Upper Hot Springs.",
                "Spot wildlife like bears and elk in Banff National Park."
            ]
        },
        Kashmir: {
            image: "./images/destination6.jpeg",
            description: "Kashmir, often called 'Paradise on Earth,' is a region in India known for its breathtaking landscapes. Nestled in the Himalayas, it features serene lakes, lush valleys, and snow-capped mountains. Visit Srinagar’s Dal Lake, explore the Mughal gardens, or take a shikara ride for an unforgettable experience.",
            highlights: [
                "Take a shikara ride on Dal Lake in Srinagar.",
                "Visit the Mughal gardens like Shalimar Bagh.",
                "Explore the scenic beauty of Gulmarg.",
                "Experience local Kashmiri culture and cuisine."
            ]
        }
    };

    // Modal Functionality
    const modal = document.getElementById("destination-modal");
    const modalImage = document.getElementById("modal-image");
    const modalTitle = document.getElementById("modal-title");
    const modalDescription = document.getElementById("modal-description");
    const modalHighlightsList = document.getElementById("modal-highlights-list");
    const closeBtn = document.querySelector(".close-btn");

    // Open Modal on View Details Click
    const viewDetailsButtons = document.querySelectorAll(".view-details-btn");
    viewDetailsButtons.forEach(button => {
        button.addEventListener("click", (e) => {
            e.stopPropagation(); // Prevent triggering the destination click event
            const destination = button.closest(".destination").getAttribute("data-destination");
            const details = destinationDetails[destination];

            // Populate Modal Content
            modalImage.style.backgroundImage = `url(${details.image})`;
            modalTitle.textContent = destination;
            modalDescription.textContent = details.description;

            // Populate Highlights
            modalHighlightsList.innerHTML = "";
            details.highlights.forEach(highlight => {
                const li = document.createElement("li");
                li.textContent = highlight;
                modalHighlightsList.appendChild(li);
            });

            // Show Modal
            modal.style.display = "flex";
            document.body.style.overflow = "hidden"; // Prevent scrolling
        });
    });

    // Close Modal on Close Button Click
    closeBtn.addEventListener("click", () => {
        modal.style.display = "none";
        document.body.style.overflow = "auto"; // Restore scrolling
    });

    // Close Modal on Outside Click
    window.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.style.display = "none";
            document.body.style.overflow = "auto"; // Restore scrolling
        }
    });
});
