<?php

namespace Hslavich\OneloginSamlBundle\Security\Logout;

use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlTokenInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;

class SamlLogoutHandler implements LogoutHandlerInterface
{
    protected $samlAuth;

    public function __construct(\OneLogin_Saml2_Auth $samlAuth)
    {
        $this->samlAuth = $samlAuth;
    }

    /**
     * This method is called by the LogoutListener when a user has requested
     * to be logged out. Usually, you would unset session variables, or remove
     * cookies, etc.
     *
     * @param Request $request
     * @param Response $response
     * @param TokenInterface $token
     */
    public function logout(Request $request, Response $response, TokenInterface $token)
    {
        if (!$token instanceof SamlTokenInterface) {
            return;
        }

        try {
            $this->samlAuth->processSLO();
        } catch (\OneLogin_Saml2_Error $e) {
            // Prepare the parameters for the SAML logout call
            $parameters = array();

            // The NameId and SessionIndex were obtained during sign on.
            // Both values should exist as attributes of the current token
            try {
                $nameId = $token->getAttribute('samlNameId');
            } catch (\InvalidArgumentException $e) {
                $nameId = null;
            }

            try {
                $sessionIndex = $token->getAttribute('samlSessionIndex');
            } catch (\InvalidArgumentException $e) {
                $sessionIndex = null;
            }

            $this->samlAuth->logout(null, $parameters, $nameId, $sessionIndex, false);
        }
    }
}
