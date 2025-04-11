document.addEventListener('keydown', (event) => {
    // Disable F5 (key code 116)
    if (event.key === 'F5' || event.keyCode === 116) {
        event.preventDefault();
        console.log('F5 disabled');
    }
    // Disable Ctrl+R
    if ((event.ctrlKey && event.key === 'r') || (event.ctrlKey && event.keyCode === 82)) {
        event.preventDefault();
        console.log('Ctrl+R disabled');
    }
});