use std::env;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RedirectKind {
    Input,
    Output,
    Append,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Redirect {
    pub(crate) kind: RedirectKind,
    pub(crate) path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommandSpec {
    pub(crate) argv: Vec<String>,
    pub(crate) redirects: Vec<Redirect>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pipeline {
    pub(crate) commands: Vec<CommandSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Pipe,
    Input,
    Output,
    Append,
}

pub(crate) fn parse_pipeline(source: &str) -> Result<Pipeline, String> {
    let tokens = lex(source)?;
    let mut pipeline = Pipeline::default();
    let mut command = CommandSpec::default();
    let mut index = 0;
    while index < tokens.len() {
        match &tokens[index] {
            Token::Word(word) => command.argv.push(word.clone()),
            Token::Pipe => {
                if command.argv.is_empty() {
                    return Err("expected a command before '|'".into());
                }
                pipeline.commands.push(core::mem::take(&mut command));
            }
            token @ (Token::Input | Token::Output | Token::Append) => {
                let Some(Token::Word(path)) = tokens.get(index + 1) else {
                    return Err("redirection requires a file path".into());
                };
                let kind = match token {
                    Token::Input => RedirectKind::Input,
                    Token::Output => RedirectKind::Output,
                    Token::Append => RedirectKind::Append,
                    _ => unreachable!(),
                };
                command.redirects.push(Redirect {
                    kind,
                    path: path.clone(),
                });
                index += 1;
            }
        }
        index += 1;
    }
    if command.argv.is_empty() {
        if pipeline.commands.is_empty() {
            return Ok(pipeline);
        }
        return Err("expected a command after '|'".into());
    }
    pipeline.commands.push(command);
    Ok(pipeline)
}

fn lex(source: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut index = 0;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut word_started = false;

    while index < chars.len() {
        let character = chars[index];
        if single_quoted {
            if character == '\'' {
                single_quoted = false;
            } else {
                word.push(character);
            }
            index += 1;
            continue;
        }
        if double_quoted {
            match character {
                '"' => double_quoted = false,
                '\\' => {
                    index += 1;
                    let Some(escaped) = chars.get(index) else {
                        return Err("trailing escape in double-quoted string".into());
                    };
                    word.push(*escaped);
                }
                '$' => expand_variable(&chars, &mut index, &mut word)?,
                _ => word.push(character),
            }
            index += 1;
            continue;
        }

        match character {
            '\'' => {
                single_quoted = true;
                word_started = true;
            }
            '"' => {
                double_quoted = true;
                word_started = true;
            }
            '\\' => {
                index += 1;
                let Some(escaped) = chars.get(index) else {
                    return Err("trailing escape".into());
                };
                word.push(*escaped);
                word_started = true;
            }
            '$' => {
                expand_variable(&chars, &mut index, &mut word)?;
                word_started = true;
            }
            '|' | '<' | '>' => {
                finish_word(&mut tokens, &mut word, &mut word_started);
                if character == '>' && chars.get(index + 1) == Some(&'>') {
                    tokens.push(Token::Append);
                    index += 1;
                } else {
                    tokens.push(match character {
                        '|' => Token::Pipe,
                        '<' => Token::Input,
                        '>' => Token::Output,
                        _ => unreachable!(),
                    });
                }
            }
            '#' if !word_started => break,
            value if value.is_whitespace() => {
                finish_word(&mut tokens, &mut word, &mut word_started);
            }
            _ => {
                word.push(character);
                word_started = true;
            }
        }
        index += 1;
    }
    if single_quoted || double_quoted {
        return Err("unterminated quoted string".into());
    }
    finish_word(&mut tokens, &mut word, &mut word_started);
    Ok(tokens)
}

fn finish_word(tokens: &mut Vec<Token>, word: &mut String, started: &mut bool) {
    if *started {
        tokens.push(Token::Word(core::mem::take(word)));
        *started = false;
    }
}

fn expand_variable(chars: &[char], index: &mut usize, output: &mut String) -> Result<(), String> {
    let start = *index + 1;
    if chars.get(start) == Some(&'{') {
        let mut end = start + 1;
        while chars.get(end).is_some_and(|character| *character != '}') {
            end += 1;
        }
        if chars.get(end) != Some(&'}') {
            return Err("unterminated parameter expansion".into());
        }
        let name: String = chars[start + 1..end].iter().collect();
        validate_variable_name(&name)?;
        output.push_str(&env::var(name).unwrap_or_default());
        *index = end;
        return Ok(());
    }
    let mut end = start;
    while chars
        .get(end)
        .is_some_and(|character| character.is_ascii_alphanumeric() || *character == '_')
    {
        end += 1;
    }
    if end == start {
        output.push('$');
        return Ok(());
    }
    let name: String = chars[start..end].iter().collect();
    output.push_str(&env::var(name).unwrap_or_default());
    *index = end - 1;
    Ok(())
}

fn validate_variable_name(name: &str) -> Result<(), String> {
    let mut characters = name.chars();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        || !characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(format!("invalid parameter name: {name}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_pipeline_and_redirections() {
        let parsed = parse_pipeline("echo 'hello world' | cat > output.txt").unwrap();
        assert_eq!(parsed.commands.len(), 2);
        assert_eq!(parsed.commands[0].argv, ["echo", "hello world"]);
        assert_eq!(parsed.commands[1].argv, ["cat"]);
        assert_eq!(
            parsed.commands[1].redirects,
            [Redirect {
                kind: RedirectKind::Output,
                path: "output.txt".into()
            }]
        );
    }

    #[test]
    fn rejects_incomplete_syntax() {
        assert!(parse_pipeline("echo hello |").is_err());
        assert!(parse_pipeline("echo hello >").is_err());
        assert!(parse_pipeline("echo 'hello").is_err());
    }
}
