<?php
/**
 * RADIUS authentication class
 *
 * PHP version 5
 *
 * Copyright (C) Villanova University 2010.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @category VuFind2
 * @package  Authentication
 * @author   Chelsea Lobdell <clobdel1@swarthmore.edu>
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     http://vufind.org/wiki/vufind2:authentication_handlers Wiki
 */
namespace our_module\Auth;
use VuFind\Exception\Auth as AuthException;

require_once 'Auth/RADIUS.php';
require_once 'Crypt/CHAP.php';

/**
 * RADIUS authentication class
 *
 * @category VuFind2
 * @package  Authentication
 * @author   Franck Borel <franck.borel@gbv.de>
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     http://vufind.org/wiki/vufind2:authentication_handlers Wiki
 */
class RADIUS extends \VuFind\Auth\AbstractBase
{
    /**
     * Username
     *
     * @var string
     */
    protected $username;

    /**
     * Institution
     *
     * @var string
     */
    protected $institution;

    /**
     * Password
     *
     * @var string
     */
    protected $password;


	/**
     * Type
     *
     * @var string
     */
    protected $authType = 'MSCHAPv2';

    /**
     * Validate configuration parameters.  This is a support method for getConfig(),
     * so the configuration MUST be accessed using $this->config; do not call
     * $this->getConfig() from within this method!
     *
     * @throws AuthException
     * @return void
     */
    protected function validateConfig()
    {
        // Check for missing parameters:
        $requiredParams = array('host', 'port', 'secret');
        foreach ($requiredParams as $param) {
            if (!isset($this->config->RADIUS->$param)
                || empty($this->config->RADIUS->$param)
            ) {
                throw new AuthException(
                    "One or more RADIUS parameters are missing. Check your config.ini!"
                );
            }
        }
    }

    /**
     * Get the requested configuration setting (or blank string if unset).
     *
     * @param string $name Name of parameter to retrieve.
     *
     * @return string
     */
    protected function getSetting($name, $default='')
    {
        $config = $this->getConfig();
        $value = isset($config->RADIUS->$name) ? $config->RADIUS->$name : $default;

        // Normalize all values to lowercase except for potentially case-sensitive
        // bind and basedn credentials.
        $doNotLower = array('secret');
        return (in_array($name, $doNotLower)) ? $value : strtolower($value);
    }

    /**
     * Attempt to authenticate the current user.  Throws exception if login fails.
     *
     * @param \Zend\Http\PhpEnvironment\Request $request Request object containing
     * account credentials.
     *
     * @throws AuthException
     * @return \VuFind\Db\Row\User Object representing logged-in user.
     */
    public function authenticate($request)
    {
        $this->username = trim($request->getPost()->get('username'));
        $this->institution = trim($request->getPost()->get('institution'));
        $this->password = trim($request->getPost()->get('password'));

        if ($this->username == ''){
            throw new AuthException('Username is blank. Please enter username.');
        }

        if ($this->institution == ''){
            throw new AuthException('Institution is blank. Please choose institution.');
        }

        if ($this->password == ''){
            throw new AuthException('Password is blank. Please enter password.');
        }

        $this->username = $this->username . '@' . $this->institution . '.edu';

        return $this->processCredentials();
    }

    /**
     * Communicate with RADIUS and authenticate user.
     *
     * Code cribbed from http://pear.php.net/manual/en/packages.authentication.auth-radius.intro.php
     *
     * @throws AuthException
     * @return \VuFind\Db\Row\User Object representing logged-in user.
     */
    public function processCredentials() {
				$classname = 'Auth_RADIUS_' . $this->authType;
			
				$rauth = new $classname($this->username, $this->password);
  			$rauth->addServer($this->getSetting('host'), 
													$this->getSetting('port'),
                          $this->getSetting('secret'), 
													$this->getSetting('timeout', 2),
                          $this->getSetting('max_tries',2));
				$rauth->username = $this->username;

        $classname = 'Crypt_CHAP_MSv2';
        $crpt = new $classname;
				$crpt->username = $this->username;
				$crpt->password = $this->password;
				$rauth->challenge = $crpt->authChallenge;
				$rauth->peerChallenge = $crpt->peerChallenge;
				$rauth->chapid = $crpt->chapid;
				$rauth->response = $crpt->challengeResponse();

				if (!$rauth->start()) {
            throw new AuthException('authentication_error_technical');
				}


				$result = $rauth->send();
        if ($result === true) {
            // credentials accepted. successful authentication.
						$rauth->close();
            return $this->processRADIUSUser();
				} else if ($result === false) {
            // credentials rejected
						$rauth->close();
            throw new AuthException('authentication_error_invalid');
				} else {
            // Auth/RADIUS returned PEAR error. Badness.
            $rauth->close();
            throw new AuthException('authentication_error_technical');
        }
		}

    /**
     * Build a User object from details obtained via RADIUS.
     *
     * @param array $data Details from ldap_get_entries call.
     *
     * @return \VuFind\Db\Row\User Object representing logged-in user.
     */
    protected function processRADIUSUser()
    {
        // User object to populate from RADIUS:
        $user = $this->getUserTable()->getByUsername($this->username);

        $user->email = $this->username;

        // Update the user in the database, then return it to the caller:
        $user->save();
        return $user;
    }
}
