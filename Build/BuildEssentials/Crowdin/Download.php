<?php

require(__DIR__ . '/Helpers.php');

$projectPath = realpath(__DIR__ . '/../../../');
echo 'Downloadingâ€¦' . PHP_EOL;
executeDownload($projectPath, $branch);
