# 🛡️ SecLog Analyzer

![CI](https://github.com/gabrielwill-gif/seclog-analyzer/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Analisador de logs de segurança em Python. Lê logs **SSH** (`auth.log`) e **web** (Apache/Nginx), detecta padrões de ataque e gera relatórios em texto, JSON ou HTML, com cada alerta mapeado para uma técnica do **MITRE ATT&CK**.

Sem dependências externas: usa apenas a biblioteca padrão do Python.

## O que ele detecta

| Regra | Severidade | MITRE ATT&CK | Descrição |
|---|---|---|---|
| `ssh_success_after_failures` | CRITICAL | T1078 | Login bem-sucedido logo após várias falhas (possível conta comprometida) |
| `ssh_bruteforce` | HIGH | T1110 | Muitas falhas de login do mesmo IP em uma janela de tempo |
| `ssh_user_enumeration` | MEDIUM | T1087 | Um IP testando muitos usuários diferentes |
| `web_sql_injection` | HIGH | T1190 | Padrões de SQL Injection na URL (inclui URL encoding duplo) |
| `web_path_traversal` | HIGH | T1190 | Tentativas de `../` e acesso a `/etc/passwd` |
| `web_command_injection` | HIGH | T1190 | Injeção de comandos de sistema |
| `web_xss` | MEDIUM | T1190 | Tentativas de Cross-Site Scripting |
| `scanner_user_agent` | MEDIUM | T1595 | User-Agent de ferramentas como sqlmap, nikto, gobuster |
| `directory_scan` | MEDIUM | T1595.003 | Rajada de respostas 404 (varredura de diretórios) |

## Instalação

```bash
git clone https://github.com/gabrielwill-gif/seclog-analyzer.git
cd seclog-analyzer
```

Requer Python 3.9 ou superior. Opcionalmente, instale o comando `seclog`:

```bash
pip install .
```

## Uso

```bash
python -m seclog samples/auth.log samples/access.log --year 2026
```

Exemplo de saída (com os logs fictícios da pasta `samples/`):

```
=== SecLog Analyzer: Relatório ===
Linhas lidas: 56 | Eventos: 55 | Alertas: 10 | IPs suspeitos: 4

[CRITICAL] 198.51.100.7    Login bem-sucedido como 'deploy' após 8 falhas: possível conta comprometida (T1078)
[HIGH    ] 203.0.113.5     12 falhas de login SSH em 10 min (12 no total) (T1110)
[HIGH    ] 198.51.100.7    8 falhas de login SSH em 10 min (8 no total) (T1110)
[HIGH    ] 203.0.113.9     SQL Injection: 4 requisição(ões). Exemplo: /produto.php?id=1' OR '1'='1 (T1190)
[HIGH    ] 203.0.113.9     Path Traversal: 1 requisição(ões). Exemplo: /download?file=../../../../etc/passwd (T1190)
[MEDIUM  ] 198.51.100.23   20 respostas 404 em 5 min: varredura de diretórios (T1595.003)
...
```

### Opções

| Opção | Descrição |
|---|---|
| `-f, --format` | `text` (padrão), `json` ou `html` |
| `-o, --output` | Salva o relatório em um arquivo |
| `--year` | Ano dos logs SSH (o syslog não inclui o ano) |
| `--ssh-failures` | Falhas para considerar força bruta (padrão: 5) |
| `--window` | Janela em minutos para força bruta (padrão: 10) |
| `--fail-on` | Retorna código 2 se houver alerta no nível indicado ou acima |

Gerar um relatório HTML:

```bash
python -m seclog samples/auth.log samples/access.log --year 2026 -f html -o relatorio.html
```

Usar em pipelines (falha se houver algo HIGH ou pior):

```bash
python -m seclog /var/log/auth.log --fail-on high
```

## Como funciona

```
seclog/
├── parsers.py     # linha de log -> Event normalizado (regex)
├── detectors.py   # regras de detecção -> Alert (janela deslizante, assinaturas)
├── report.py      # texto, JSON e HTML
├── models.py      # Event e Alert (dataclasses)
└── cli.py         # interface de linha de comando
```

1. **Parsing:** cada linha vira um `Event` com IP, horário, usuário, URL e status.
2. **Detecção:** cada regra recebe a lista de eventos e devolve alertas. Regras de frequência usam uma **janela deslizante** para medir o pico de eventos em um intervalo de tempo.
3. **Relatório:** alertas ordenados por severidade, com mapeamento MITRE ATT&CK.

Para adicionar uma regra nova, crie uma função em `detectors.py` que receba `(events, thresholds)` e retorne uma lista de `Alert`, e registre em `RULES`.

## Testes

```bash
python -m unittest discover -s tests -v
```

Os testes rodam automaticamente no GitHub Actions (Python 3.9, 3.11 e 3.12).

## Limitações

- Detecção baseada em assinaturas e limiares. Pode gerar falsos positivos e não substitui um SIEM.
- Suporta apenas IPv4 e os formatos de log citados acima.
- Use somente em logs de sistemas que você administra ou tem autorização para analisar.

## Roadmap

- [ ] Suporte a IPv6
- [ ] Consulta de reputação de IP
- [ ] Geolocalização dos IPs atacantes
- [ ] Parser para logs do Windows Event Log
- [ ] Modo "tail" para monitoramento em tempo real

## Licença

MIT
