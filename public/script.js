function togglePassword(fieldId) {
    const passwordField = document.getElementById(fieldId);
    if (passwordField.type === "password") {
        passwordField.type = "text";
    } else {
        passwordField.type = "password";
    }
}
let index = 0;

function moveSlide(step) {
    const slides = document.querySelectorAll(".slide");
    index = (index + step + slides.length) % slides.length;
    document.querySelector(".carousel").style.transform = `translateX(-${index * 100}%)`;
}

// Auto-slide every 4 seconds
setInterval(() => moveSlide(1), 4000);
