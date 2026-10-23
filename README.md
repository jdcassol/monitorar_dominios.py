# Monitoramento de expiração de domínios

Monitora:
- cassolcenterlar.com.br
- cassol.com.br
- debus.com.br
- avallonturismo.com.br
- agrograopalotina.com.br
- jltech.com.br

O workflow do GitHub Actions executa o script semanalmente às segundas-feiras às 08:00 de Brasília e permite execução manual na aba Actions.

## Configuração do e-mail

No repositório, acesse **Settings → Secrets and variables → Actions → New repository secret** e crie:
- SMTP_HOST
- SMTP_PORT (normalmente 587)
- SMTP_USER
- SMTP_PASSWORD
- ALERT_FROM
- ALERT_TO

Use os dados SMTP do seu provedor. Não coloque senhas no código nem as envie nesta conversa.

## Teste

1. Abra a aba **Actions**.
2. Selecione **Monitorar expiração de domínios**.
3. Clique em **Run workflow**.
4. Confira os logs, o artefato do relatório e a chegada do e-mail.

O script consulta o RDAP do Registro.br e tenta WHOIS como alternativa. Se não conseguir confirmar uma data, marca a consulta como falha e não inventa o vencimento. A execução semanal pode não detectar um alerta de 1 dia a tempo; para garantir esse alerta, altere o agendamento para diário.
