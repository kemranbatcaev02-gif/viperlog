use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "viperlog",
    author = "kemranbatcaev02-gif",
    version = "0.1.0",
    about = "⚡ Сверхбыстрый утилизатор и цензор логов на Rust с SIMD-ускорением",
    long_about = "ViperLog сканирует текст и структурированные логи на наличие конфиденциальных данных \
(банковские карты, токены, email, IP) с использованием SIMD-инструкций и параллельной обработки."
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Входной файл (по умолчанию STDIN)
    #[arg(short, long, global = true)]
    pub input: Option<PathBuf>,

    /// Выходной файл (по умолчанию STDOUT)
    #[arg(short, long, global = true)]
    pub output: Option<PathBuf>,

    /// Режим аудита: вывод статистики без перезаписи данных
    #[arg(short, long, global = true)]
    pub audit: bool,

    /// Перезапись входного файла на месте
    #[arg(long, global = true)]
    pub in_place: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Маскирование конфиденциальных данных
    Scrub {
        #[arg(short, long)]
        input: Option<PathBuf>,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Аудит безопасности: отчет об утечках и скорость обработки без изменения файлов
    Audit {
        /// Путь к файлу логов для анализа
        file: PathBuf,
    },

    /// Интерактивная демонстрация маскирования данных
    Demo,
}
