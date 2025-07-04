<?php

namespace Drupal\userspice_oauth\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Configure UserSpice OAuth settings for this site.
 */
class SettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'userspice_oauth_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['userspice_oauth.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('userspice_oauth.settings');

    $form['userspice_server_url'] = [
      '#type' => 'url',
      '#title' => $this->t('UserSpice Server URL'),
      '#description' => $this->t('The base URL of your UserSpice installation (e.g., https://example.com/usersc/).'),
      '#default_value' => $config->get('userspice_server_url'),
      '#required' => TRUE,
    ];

    $form['client_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Client ID'),
      '#description' => $this->t('The Client ID obtained from your UserSpice OAuth Server plugin.'),
      '#default_value' => $config->get('client_id'),
      '#required' => TRUE,
    ];

    $form['client_secret'] = [
      '#type' => 'textfield', // In production, consider key_auth module for better secret storage
      '#title' => $this->t('Client Secret'),
      '#description' => $this->t('The Client Secret obtained from your UserSpice OAuth Server plugin.'),
      '#default_value' => $config->get('client_secret'),
      '#required' => TRUE,
    ];

    $form['us_auth_endpoint_path'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Authorization Endpoint Path'),
      '#description' => $this->t('Path to UserSpice authorization endpoint relative to server URL (e.g., usersc/plugins/oauth_server/auth.php).'),
      '#default_value' => $config->get('us_auth_endpoint_path') ?: 'usersc/plugins/oauth_server/auth.php',
    ];

    $form['us_token_endpoint_path'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Token Endpoint Path'),
      '#description' => $this->t('Path to UserSpice token endpoint relative to server URL (e.g., usersc/plugins/oauth_server/auth.php).'),
      '#default_value' => $config->get('us_token_endpoint_path') ?: 'usersc/plugins/oauth_server/auth.php',
    ];

    $form['us_userinfo_endpoint_path'] = [
      '#type' => 'textfield',
      '#title' => $this->t('User Info Endpoint Path'),
      '#description' => $this->t('Path to UserSpice user info API endpoint relative to server URL (e.g., usersc/plugins/oauth_server/api.php).'),
      '#default_value' => $config->get('us_userinfo_endpoint_path') ?: 'usersc/plugins/oauth_server/api.php',
    ];

    $form['scope'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Scope'),
      '#description' => $this->t('Space-separated list of scopes to request (e.g., profile email). `email` is recommended.'),
      '#default_value' => $config->get('scope') ?: 'profile email',
    ];

    $form['create_drupal_user'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Auto-create Drupal User'),
      '#description' => $this->t('If enabled, a new Drupal user will be created if one doesn\'t exist for the UserSpice account.'),
      '#default_value' => $config->get('create_drupal_user') ?? TRUE, // Default to TRUE if not set
    ];

    // Add options for how to map UserSpice roles/attributes to Drupal roles if needed in future.
    // For now, new users get default Drupal authenticated role.

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $this->config('userspice_oauth.settings')
      ->set('userspice_server_url', rtrim($form_state->getValue('userspice_server_url'), '/'))
      ->set('client_id', $form_state->getValue('client_id'))
      ->set('client_secret', $form_state->getValue('client_secret'))
      ->set('us_auth_endpoint_path', $form_state->getValue('us_auth_endpoint_path'))
      ->set('us_token_endpoint_path', $form_state->getValue('us_token_endpoint_path'))
      ->set('us_userinfo_endpoint_path', $form_state->getValue('us_userinfo_endpoint_path'))
      ->set('scope', $form_state->getValue('scope'))
      ->set('create_drupal_user', $form_state->getValue('create_drupal_user'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
