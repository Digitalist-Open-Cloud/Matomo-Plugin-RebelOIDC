<?php

namespace Piwik\Plugins\RebelOIDC;

/**
 * One-shot session flag that tells the login page to show the generic "login failed" message.
 * Pure helper (operates on the array it is given) so it can be unit tested outside Matomo.
 */
class LoginFailureFlag
{
    public const KEY = 'rebeloidc_login_failed';

    public static function raise(array &$session): void
    {
        $session[self::KEY] = true;
    }

    /**
     * Returns true once after raise(), then false. Also clears the flag.
     */
    public static function take(array &$session): bool
    {
        $raised = !empty($session[self::KEY]);
        unset($session[self::KEY]);
        return $raised;
    }

    public static function clear(array &$session): void
    {
        unset($session[self::KEY]);
    }
}
