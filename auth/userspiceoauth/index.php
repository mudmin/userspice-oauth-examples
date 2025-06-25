<?php
/**
 * Placeholder index file for UserSpice OAuth Authentication Plugin.
 * This file is typically not directly accessed but prevents directory listing
 * and can be used for a simple redirect if needed.
 *
 * @package    auth_userspiceoauth
 * @copyright  2023 UserSpice OAuth Integrator (AI)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');

// Redirect to the Moodle front page or login page.
$urltogo = $CFG->wwwroot . '/login/index.php';
redirect($urltogo);
exit;
