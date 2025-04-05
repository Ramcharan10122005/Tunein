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

// Add animation classes to elements when they come into view
document.addEventListener('DOMContentLoaded', function() {
    // Add fade-in animation to main content
    const mainContent = document.querySelector('main');
    if (mainContent) {
        mainContent.classList.add('animate-fade-in');
    }

    // Add slide animations to cards
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.classList.add('animate-slide-bottom');
        card.style.animationDelay = `${index * 0.1}s`;
    });

    // Add hover effects to buttons
    const actionButtons = document.querySelectorAll('button, .btn');
    actionButtons.forEach(button => {
        button.classList.add('hover-lift');
    });

    // Add image hover zoom effect
    const images = document.querySelectorAll('img');
    images.forEach(img => {
        const wrapper = document.createElement('div');
        wrapper.className = 'img-hover-zoom';
        img.parentNode.insertBefore(wrapper, img);
        wrapper.appendChild(img);
    });

    // Add loading spinner for async operations
    function showLoading() {
        const spinner = document.createElement('div');
        spinner.className = 'loading-spinner';
        document.body.appendChild(spinner);
    }

    function hideLoading() {
        const spinner = document.querySelector('.loading-spinner');
        if (spinner) {
            spinner.remove();
        }
    }

    // Example usage for async operations
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', () => {
            showLoading();
        });
    });

    // Add bounce animation to logo
    const logo = document.querySelector('.tunein');
    if (logo) {
        logo.classList.add('animate-bounce');
    }
    
    // Add float animation to music player controls
    const playBtn = document.querySelector('.music-controls .play-btn');
    if (playBtn) {
        playBtn.classList.add('animate-float');
    }
    
    // Add shimmer effect to progress bar
    const progressBar = document.querySelector('.progress-bar');
    if (progressBar) {
        progressBar.classList.add('animate-shimmer');
    }
    
    // Add glow effect to premium elements
    const premiumElements = document.querySelectorAll('.premium-badge, .premium-button');
    premiumElements.forEach(element => {
        element.classList.add('animate-glow');
    });
    
    // Add text gradient animation to headings
    const headings = document.querySelectorAll('h1, h2');
    headings.forEach(heading => {
        heading.classList.add('animate-text-gradient');
    });
    
    // Add reveal class to sections for scroll animation
    const sections = document.querySelectorAll('section, .card, .song');
    sections.forEach(section => {
        section.classList.add('reveal');
    });
    
    // Add shake animation to error messages
    const errorMessages = document.querySelectorAll('.error-message');
    errorMessages.forEach(error => {
        error.classList.add('animate-shake');
    });
    
    // Add rotate animation to loading icons
    const loadingIcons = document.querySelectorAll('.loading-icon');
    loadingIcons.forEach(icon => {
        icon.classList.add('animate-rotate');
    });
    
    // Add blink animation to notifications
    const notifications = document.querySelectorAll('.notification');
    notifications.forEach(notification => {
        notification.classList.add('animate-blink');
    });
    
    // Enhanced button click effect
    const primaryButtons = document.querySelectorAll('.btn-primary');
    primaryButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const x = e.clientX - e.target.offsetLeft;
            const y = e.clientY - e.target.offsetTop;
            
            const ripple = document.createElement('span');
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;
            
            this.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
});

// Scroll Reveal Animation
function revealOnScroll() {
    const reveals = document.querySelectorAll('.reveal');
    
    reveals.forEach(element => {
        const windowHeight = window.innerHeight;
        const elementTop = element.getBoundingClientRect().top;
        const elementVisible = 150;
        
        if (elementTop < windowHeight - elementVisible) {
            element.classList.add('active');
        }
    });
}

window.addEventListener('scroll', revealOnScroll);
window.addEventListener('load', revealOnScroll);

// Create animated background elements
function createAnimatedBackground() {
    const background = document.createElement('div');
    background.className = 'login-background';
    
    // Create particles container
    const particles = document.createElement('div');
    particles.className = 'particles';
    
    // Create sound waves
    const soundWaves = document.createElement('div');
    soundWaves.className = 'sound-waves';
    
    // Create wave bars
    for (let i = 0; i < 20; i++) {
        const waveBar = document.createElement('div');
        waveBar.className = 'wave-bar';
        waveBar.style.animationDelay = `${i * 0.1}s`;
        soundWaves.appendChild(waveBar);
    }
    
    // Create particles
    for (let i = 0; i < 30; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        
        // Random positions and movements
        const tx = Math.random() * 200 - 100;
        const ty = Math.random() * 200 - 100;
        const tz = Math.random() * 100;
        
        particle.style.setProperty('--tx', `${tx}px`);
        particle.style.setProperty('--ty', `${ty}px`);
        particle.style.setProperty('--tz', `${tz}px`);
        
        particle.style.left = `${Math.random() * 100}%`;
        particle.style.top = `${Math.random() * 100}%`;
        particle.style.animationDelay = `${Math.random() * 8}s`;
        
        particles.appendChild(particle);
    }
    
    // Create pulsating rings
    for (let i = 0; i < 3; i++) {
        const ring = document.createElement('div');
        ring.className = 'ring';
        ring.style.left = `${50 + (i - 1) * 10}%`;
        ring.style.top = `${50 + (i - 1) * 10}%`;
        ring.style.animationDelay = `${i * 1.3}s`;
        background.appendChild(ring);
    }
    
    // Create floating musical notes
    const notes = ['♪', '♫', '♬', '♩'];
    for (let i = 0; i < 10; i++) {
        const note = document.createElement('div');
        note.className = 'musical-note';
        note.textContent = notes[Math.floor(Math.random() * notes.length)];
        
        // Random start and end positions
        const startX = Math.random() * window.innerWidth;
        const startY = window.innerHeight + 50;
        const endX = Math.random() * window.innerWidth;
        const endY = -50;
        
        note.style.setProperty('--startX', `${startX}px`);
        note.style.setProperty('--startY', `${startY}px`);
        note.style.setProperty('--endX', `${endX}px`);
        note.style.setProperty('--endY', `${endY}px`);
        
        note.style.left = `${startX}px`;
        note.style.top = `${startY}px`;
        note.style.animationDelay = `${Math.random() * 6}s`;
        
        background.appendChild(note);
    }
    
    background.appendChild(particles);
    background.appendChild(soundWaves);
    
    // Add background to login page
    const loginContainer = document.querySelector('.login-container');
    if (loginContainer) {
        loginContainer.parentElement.insertBefore(background, loginContainer);
    }
}

// Initialize animation when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    if (document.querySelector('.login-container')) {
        createAnimatedBackground();
        
        // Recreate floating notes periodically
        setInterval(() => {
            const oldNotes = document.querySelectorAll('.musical-note');
            oldNotes.forEach(note => note.remove());
            
            const notes = ['♪', '♫', '♬', '♩'];
            for (let i = 0; i < 10; i++) {
                const note = document.createElement('div');
                note.className = 'musical-note';
                note.textContent = notes[Math.floor(Math.random() * notes.length)];
                
                const startX = Math.random() * window.innerWidth;
                const startY = window.innerHeight + 50;
                const endX = Math.random() * window.innerWidth;
                const endY = -50;
                
                note.style.setProperty('--startX', `${startX}px`);
                note.style.setProperty('--startY', `${startY}px`);
                note.style.setProperty('--endX', `${endX}px`);
                note.style.setProperty('--endY', `${endY}px`);
                
                note.style.left = `${startX}px`;
                note.style.top = `${startY}px`;
                note.style.animationDelay = `${Math.random() * 6}s`;
                
                document.querySelector('.login-background').appendChild(note);
            }
        }, 6000);
    }
});
