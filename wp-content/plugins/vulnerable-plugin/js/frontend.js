/**
 * Vulnerable Demo Plugin - Frontend JavaScript
 * Contains intentional DOM-based XSS vulnerabilities for security testing
 */

(function($) {
    'use strict';

    // DOM XSS Vulnerability #1: innerHTML with user input
    function displayUserMessage() {
        var params = new URLSearchParams(window.location.search);
        var message = params.get('msg');

        if (message) {
            // XSS: Using innerHTML with unsanitized URL parameter
            document.getElementById('user-message').innerHTML = message;
        }
    }

    // DOM XSS Vulnerability #2: Using vdpData without sanitization
    function showWelcome() {
        var container = document.querySelector('.welcome-container');
        if (container && typeof vdpData !== 'undefined') {
            // XSS: Inserting server-side localized data without sanitization
            container.innerHTML = '<h2>Welcome!</h2><p>' + vdpData.userInput + '</p>';
        }
    }

    // DOM XSS Vulnerability #3: document.write with URL hash
    function processHashData() {
        var hash = window.location.hash.substring(1);
        if (hash) {
            // XSS: document.write with URL fragment
            document.write('<div class="hash-content">' + decodeURIComponent(hash) + '</div>');
        }
    }

    // DOM XSS Vulnerability #4: eval() with user data
    function executeCallback() {
        var params = new URLSearchParams(window.location.search);
        var callback = params.get('callback');

        if (callback) {
            // XSS: eval() with URL parameter - extremely dangerous
            eval(callback + '()');
        }
    }

    // DOM XSS Vulnerability #5: jQuery html() method
    function loadDynamicContent() {
        var contentId = new URLSearchParams(window.location.search).get('content');

        // XSS: jQuery .html() with unsanitized parameter
        if (contentId) {
            $('#dynamic-area').html('<div class="loaded">' + contentId + '</div>');
        }
    }

    // DOM XSS Vulnerability #6: Setting href attribute
    function updateLinks() {
        var targetUrl = new URLSearchParams(window.location.search).get('redirect');

        if (targetUrl) {
            // XSS: javascript: URLs can be injected
            document.querySelector('.redirect-link').href = targetUrl;
        }
    }

    // DOM XSS Vulnerability #7: setAttribute with user input
    function customizeButton() {
        var btnAction = new URLSearchParams(window.location.search).get('action');
        var btn = document.getElementById('custom-btn');

        if (btn && btnAction) {
            // XSS: Setting onclick handler with user input
            btn.setAttribute('onclick', btnAction);
        }
    }

    // DOM XSS Vulnerability #8: postMessage handler without origin check
    window.addEventListener('message', function(event) {
        // XSS: No origin verification - accepts messages from any source
        var data = event.data;
        if (data.type === 'updateContent') {
            document.getElementById('msg-content').innerHTML = data.content;
        }
    });

    // AJAX handler with unsafe response handling
    function submitComment() {
        var comment = $('#comment-input').val();
        var name = $('#name-input').val();

        $.ajax({
            url: vdpData.ajaxUrl,
            type: 'POST',
            data: {
                action: 'vdp_update_comment',
                comment: comment,
                user_name: name
            },
            success: function(response) {
                // XSS: Inserting AJAX response without sanitization
                $('#comment-result').html(response);
            }
        });
    }

    // Initialize on document ready
    $(document).ready(function() {
        displayUserMessage();
        showWelcome();
        loadDynamicContent();
        updateLinks();
        customizeButton();

        $('#submit-comment').on('click', submitComment);
    });

})(jQuery);
