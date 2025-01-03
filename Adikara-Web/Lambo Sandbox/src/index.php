<?php

class Helper
{
    public string $file = '/tmp/sandbox';

    public function __construct() {}

    public function process(): void
    {
        echo file_get_contents($this->file);
    }
}

class Sandbox
{
    private string $uploadDir = '/tmp/sandbox';

    public function displayInterface(): void
    {
        echo '<!DOCTYPE html>
        <html>
        <head>
	    <title>Sandbox CTF Challenge</title>
	    <link rel="stylesheet" href="https://cdn.simplecss.org/simple.min.css">
        </head>
        <body>
            <h1>Sandbox CTF Challenge</h1>
            <form action="" method="post" enctype="multipart/form-data">
                <label for="file">Upload your PHAR file:</label>
                <input type="file" name="file" id="file" required>
                <button type="submit">Upload</button>
            </form>
            <div id="result">';

        $this->handleFileUpload();

        echo '</div>
        </body>
        </html>';
    }

    private function handleFileUpload(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
            $this->processPharFile($_FILES['file']['tmp_name']);
        }
    }

    private function processPharFile(string $filePath): void
    {
        try {
            if (!is_dir($this->uploadDir)) {
                mkdir($this->uploadDir, 0755, true);
            }

            $targetPath = $this->uploadDir . '/' . basename($filePath) . '.phar';
            move_uploaded_file($filePath, $targetPath);

            $phar = new Phar($targetPath);
            $phar->extractTo($this->uploadDir, null, true);

            $dataPath = $this->uploadDir . '/magic_happens_here';
            if (file_exists($dataPath)) {
                $data = file_get_contents($dataPath);
                $unserializedData = unserialize($data);

                if ($unserializedData instanceof Helper) {
                    $unserializedData->process();
                } else {
                    echo "<p>Invalid data in PHAR file.</p>";
                }

                // Delete the lol file after processing
                unlink($dataPath);
            } else {
                echo "<p>Data file not found in PHAR archive.</p>";
            }

            // Optionally delete the extracted PHAR file as well
            unlink($targetPath);
        } catch (Exception $e) {
            echo "<p>Error processing PHAR file: " . htmlspecialchars($e->getMessage()) . "</p>";
        }
    }
}

$app = new Sandbox();
$app->displayInterface();

