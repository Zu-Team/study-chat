// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Force dark theme always - no light mode toggle
(function() {
    'use strict';
    
    // Ensure dark theme is always applied
    function enforceDarkTheme() {
        const html = document.documentElement;
        if (!html.hasAttribute('data-theme') || html.getAttribute('data-theme') !== 'dark') {
            html.setAttribute('data-theme', 'dark');
            html.classList.add('dark');
        }
        
        // Prevent any theme switching
        html.style.colorScheme = 'dark';
    }
    
    // Apply on page load
    enforceDarkTheme();
    
    // Apply on DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', enforceDarkTheme);
    }
    
    // Apply immediately if already loaded
    if (document.readyState === 'interactive' || document.readyState === 'complete') {
        enforceDarkTheme();
    }
    
    // Watch for any changes to the theme attribute and force it back to dark
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'attributes' && mutation.attributeName === 'data-theme') {
                const html = document.documentElement;
                if (html.getAttribute('data-theme') !== 'dark') {
                    enforceDarkTheme();
                }
            }
        });
    });
    
    observer.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['data-theme', 'class']
    });
})();
