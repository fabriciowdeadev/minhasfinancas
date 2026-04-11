-- Schema do Controle de Finanças
-- Execute no MySQL se quiser criar as tabelas manualmente.
-- O servidor Node.js cria as tabelas automaticamente na primeira inicialização.

CREATE TABLE IF NOT EXISTS users (
  password_hash VARCHAR(255) NOT NULL PRIMARY KEY,
  created_at    TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- MesLancamento é armazenado como INT no formato MMYYYY
-- onde o mês não tem zero à esquerda.
-- Exemplos: Abril/2026 = 42026 | Outubro/2026 = 102026 | Janeiro/2026 = 12026
-- Fórmula: MesLancamento = mês * 10000 + ano

CREATE TABLE IF NOT EXISTS lancamentos (
  id               INT AUTO_INCREMENT PRIMARY KEY,
  UserPasswordHash VARCHAR(255)              NOT NULL,
  Tipo             ENUM('Debitar','Creditar') NOT NULL,
  MesLancamento    INT                       NOT NULL,
  InicioPagamento  VARCHAR(10)               DEFAULT NULL,  -- DD/MM/YYYY
  Parcelas         INT                       DEFAULT 1,
  Cartao_ou_Conta  VARCHAR(100)              DEFAULT NULL,
  Grupo            VARCHAR(100)              DEFAULT NULL,
  Observacao       TEXT                      DEFAULT NULL,
  ValorParcela     DECIMAL(15,2)             DEFAULT NULL,
  Valor            DECIMAL(15,2)             DEFAULT NULL,
  created_at       TIMESTAMP                 DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (UserPasswordHash),
  INDEX idx_mes  (MesLancamento),
  FOREIGN KEY (UserPasswordHash) REFERENCES users(password_hash) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Exemplo de inserção manual:
-- INSERT INTO users (password_hash) VALUES ('$2a$10$z26dUU7ZJ4ZIq0bjcTeR2eoF58qVCSUe3RyoO4Vr/DYSzZjkDyt6S');
-- INSERT INTO lancamentos (UserPasswordHash, Tipo, MesLancamento, InicioPagamento, Parcelas, Cartao_ou_Conta, Grupo, Observacao, ValorParcela, Valor)
-- VALUES ('$2a$10$z26dUU7ZJ4ZIq0bjcTeR2eoF58qVCSUe3RyoO4Vr/DYSzZjkDyt6S', 'Debitar', 42026, '15/05/2026', 10, 'Caixa Black', 'Utensilios', 'Compra de coisa para casa', 50, 500);
