<?php

require(__DIR__ . '/Helpers.php');

$projectPath = realpath(__DIR__ . '/../../../');
echo 'Uploadingâ€¦' . PHP_EOL;
executeUpload($projectPath, $uploadTranslations, $branch);
