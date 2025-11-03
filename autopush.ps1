# Script para subir automáticamente los cambios a Git
# Guarda este archivo como autopush.ps1 en la raíz de tu proyecto

$commitMsg = "Auto commit: cambios automáticos"

git add .
git commit -m $commitMsg
git push
