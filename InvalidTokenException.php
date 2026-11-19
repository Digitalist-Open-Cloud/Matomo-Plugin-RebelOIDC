<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

/**
 * Thrown when an ID token / JWT fails verification. The message is logged and
 * must never contain the token itself.
 */
class InvalidTokenException extends \Exception
{
}
