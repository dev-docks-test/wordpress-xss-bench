<?php
/**
 * Plugin Name: Vulnerable Demo Plugin
 * Description: WordPress plugin with intentional XSS vulnerabilities for security testing
 * Version: 1.0.0
 * Author: CRA Benchmark
 */

// XSS Vulnerability #1: Reflected XSS via GET parameter (CRITICAL)
// User input directly echoed without sanitization
function vdp_search_results() {
    if (isset($_GET['search'])) {
        $search_term = $_GET['search'];  // Unsanitized input
        echo '<div class="search-results">';
        echo '<h2>Search Results for: ' . $search_term . '</h2>';  // XSS: direct output
        echo '</div>';
    }
}

// XSS Vulnerability #2: Stored XSS in settings (HIGH)
// Admin setting stored without sanitization, displayed without escaping
function vdp_save_settings() {
    if (isset($_POST['vdp_welcome_message'])) {
        update_option('vdp_welcome_message', $_POST['vdp_welcome_message']);  // No sanitization
    }
}

function vdp_display_welcome() {
    $message = get_option('vdp_welcome_message', 'Welcome!');
    echo '<div class="welcome-banner">' . $message . '</div>';  // XSS: unescaped output
}

// XSS Vulnerability #3: AJAX handler without nonce or escaping (HIGH)
add_action('wp_ajax_vdp_update_comment', 'vdp_ajax_update_comment');
add_action('wp_ajax_nopriv_vdp_update_comment', 'vdp_ajax_update_comment');

function vdp_ajax_update_comment() {
    // Missing: wp_verify_nonce() check
    $comment_content = $_POST['comment'];  // No sanitization
    $user_name = $_POST['user_name'];

    // Output directly without JSON encoding or escaping
    echo "Comment by " . $user_name . ": " . $comment_content;
    wp_die();
}

// XSS Vulnerability #4: DOM-based XSS setup (MEDIUM)
function vdp_enqueue_scripts() {
    wp_enqueue_script('vdp-frontend', plugin_dir_url(__FILE__) . 'js/frontend.js');

    // Passing unescaped data to JavaScript
    wp_localize_script('vdp-frontend', 'vdpData', array(
        'userInput' => isset($_GET['msg']) ? $_GET['msg'] : '',  // No escaping for JS
        'ajaxUrl' => admin_url('admin-ajax.php')
    ));
}
add_action('wp_enqueue_scripts', 'vdp_enqueue_scripts');

// XSS Vulnerability #5: Attribute injection (MEDIUM)
function vdp_user_profile_link($user_id) {
    $custom_url = get_user_meta($user_id, 'profile_url', true);
    // XSS: Missing esc_url() and esc_attr()
    echo '<a href="' . $custom_url . '" title="' . get_the_author_meta('display_name', $user_id) . '">Profile</a>';
}

// XSS Vulnerability #6: Shortcode with reflected input (HIGH)
add_shortcode('vdp_greet', 'vdp_greet_shortcode');

function vdp_greet_shortcode($atts) {
    $atts = shortcode_atts(array(
        'name' => isset($_GET['name']) ? $_GET['name'] : 'Guest'  // From URL
    ), $atts);

    // XSS: shortcode output not escaped
    return '<span class="greeting">Hello, ' . $atts['name'] . '!</span>';
}

// XSS Vulnerability #7: Widget with unescaped title (MEDIUM)
class VDP_Widget extends WP_Widget {
    public function __construct() {
        parent::__construct('vdp_widget', 'Vulnerable Widget');
    }

    public function widget($args, $instance) {
        echo $args['before_widget'];
        // XSS: Missing esc_html() on title
        echo $args['before_title'] . $instance['title'] . $args['after_title'];
        echo $instance['content'];  // XSS: unescaped content
        echo $args['after_widget'];
    }

    public function update($new_instance, $old_instance) {
        // Missing sanitization
        $instance = array();
        $instance['title'] = $new_instance['title'];  // Should use sanitize_text_field()
        $instance['content'] = $new_instance['content'];  // Should use wp_kses_post()
        return $instance;
    }
}

// Register widget
add_action('widgets_init', function() {
    register_widget('VDP_Widget');
});

// XSS Vulnerability #8: Meta box output (MEDIUM)
function vdp_add_meta_box() {
    add_meta_box('vdp_meta', 'Custom Data', 'vdp_meta_box_callback', 'post');
}
add_action('add_meta_boxes', 'vdp_add_meta_box');

function vdp_meta_box_callback($post) {
    $custom_data = get_post_meta($post->ID, '_vdp_custom_data', true);
    ?>
    <label>Custom Data:</label>
    <input type="text" name="vdp_custom_data" value="<?php echo $custom_data; ?>" />
    <?php
    // XSS: Missing esc_attr() in input value attribute
}

// Activation hook
register_activation_hook(__FILE__, function() {
    add_option('vdp_welcome_message', 'Welcome to our site!');
});
