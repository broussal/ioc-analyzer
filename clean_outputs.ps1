# Script de nettoyage des rapports générés
# Usage: .\clean_outputs.ps1

Write-Host "🗑️  Nettoyage des rapports..." -ForegroundColor Yellow

# Supprime tous les fichiers HTML et JSON dans outputs/
Remove-Item -Path "outputs\*.html" -ErrorAction SilentlyContinue
Remove-Item -Path "outputs\*.json" -ErrorAction SilentlyContinue

# Compte les fichiers restants (doit être juste .gitkeep)
$remaining = (Get-ChildItem -Path "outputs\" -File).Count

if ($remaining -eq 1) {
    Write-Host "✅ Nettoyage terminé ! outputs/ est propre." -ForegroundColor Green
    Write-Host "📁 Fichier restant : .gitkeep (normal)" -ForegroundColor Cyan
} else {
    Write-Host "⚠️  Fichiers restants: $remaining" -ForegroundColor Yellow
    Get-ChildItem -Path "outputs\" -File | Format-Table Name, Length
}

Write-Host ""
Write-Host "🚀 Prêt pour de nouveaux tests !" -ForegroundColor Green
