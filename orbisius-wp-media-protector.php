<?php
/*
  Plugin Name: Orbisius WP Media Protector
  Plugin URI: http://orbisius.com/products/wordpress-plugins/orbisius-wp-media-protector/
  Description: Restricts access to WP Media uploads to logged in users only. Requires some rules to be added in .htaccess file as well. This plugin must be saved in wp-content/mu-plugins/ folder. See plugin page for more details.
  Version: 1.0.0
  Author: Svetoslav Marinov (Slavi)
  Author URI: http://orbisius.com
 */

/**
This needs to be saved to wp-content/mu-plugins/orbisius-wp-media-protector.php
That way it will run automatically.

Add the following lines to the .htaccess file (usually in the root WP folder).

# Protect all files within the uploads folder
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^(.*?/?)wp-content/uploads/.* [NC]
    RewriteCond %{REQUEST_URI} !orbisius_media_protector [NC]
	RewriteRule . %1/?orbisius_media_protector=%{REQUEST_URI} [L,QSA]
</IfModule>

 * @todo: Ideas for improvement
 * check for a given role before granting access e.g. editor or administrator
*/

$prot_obj = new orbisius_wp_media_uploads_protector();
add_action( 'init', [ $prot_obj, 'protect_uploads' ], 0 );

/**
 * @author Svetoslav Marinov (SLAVI) | http://orbisius.com
 */
class orbisius_wp_media_uploads_protector {
    function protect_uploads() {
        if ( ! empty( $_REQUEST['orbisius_media_protector'] ) ) {
            $req_file = $_REQUEST['orbisius_media_protector'];
            
            if ( ! $this->check_file( $req_file ) ) {
                wp_die( "Invalid request.", 'Error' );
            }
            
            if ( headers_sent() ) {
                wp_die( "Cannot deliver the file. Headers have already been sent.", 'Error' );
            }
            
            if ( is_user_logged_in() ) {
                // Don't cache the file because the user may log out and try to access it again.
                // http://stackoverflow.com/questions/13640109/how-to-prevent-browser-cache-for-php-site
                header( "Cache-Control: no-store, no-cache, must-revalidate, max-age=0" );
                header( "Cache-Control: post-check=0, pre-check=0", false );
                header( "Cache-Control: no-store, no-cache, must-revalidate, max-age=0" );
                header( "Pragma: no-cache" );
                header( "Expires: Sun, 19 Apr 1981 06:00:00 GMT" );
                header( "Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT" );
                header( "Connection: close" );
                
                // Let's use this just in case.
                nocache_headers();
    
                $file = ABSPATH . $req_file;

                if ( file_exists( $file ) ) {
                    $content_type = 'application/octet-stream';
                    $type_rec = wp_check_filetype( $file );
                    
                    if ( ! empty( $type_rec['type'] ) ) {
                        $content_type = $type_rec['type'];
                    }
                 
                    // It seems fpassthru sends the correct headers or the 
                    // browsers are pretty smart to detect it.
                    header( "Content-type: $content_type" );
                 
                    // Offer documents for download
                    if ( preg_match( '#\.(txt|rtf|pages|pdf|docx?|xlsx?|pptx?)$#si', $file ) ) {
                        header( sprintf( 'Content-Disposition: attachment; filename="%s"', basename( $file ) ) );          
                        
                        // The user needs to know how big the file is.
                        $size = filesize( $file );
                        header( "Content-length: $size" );
                    }

                    $fp = fopen( $file, 'rb' );

                    if (!empty($fp)) {
	                    flock($fp, LOCK_SH);
                        fpassthru($fp);
	                    flock($fp, LOCK_UN);
	                    fclose($fp);
                    } else {
	                    status_header( 404 );
	                    echo "Cannot open file.";
                    }
                } else {
                    status_header( 404 );
                    global $wp_query;
                    $wp_query->set_404();
                    echo "File not found.";
                }
            } else {
                $loc = wp_login_url();
                $loc = add_query_arg( 'redirect_to', $req_file, $loc );
                wp_safe_redirect( $loc );
            }
            
            // we either have served the file or have sent the user to the login page.
            exit;
        }
    }
    
    /**
     * Very strict checks for file. No encoded stuff.
     * Alpha numeric with an extension.
     * @param str $req_file
     * @return bool
     */
    function check_file( $req_file ) {
        $ok = 0;
        
        if (       ( strpos( $req_file, '..' ) === false ) 
                && ( strpos( $req_file, '/wp-content/uploads/' ) !== false )
                && preg_match( '#^/wp-content/uploads/[\.\s\w\-\/\\\]+\.([a-z]{2,5})$#si', $req_file ) ) {
            $ok = 1;
        }
                
        return $ok;
    }
}
