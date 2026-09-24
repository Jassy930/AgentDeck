use std::collections::HashMap;

use markdown::{ParseOptions, mdast::Node};

pub(super) fn images_as_links(source: &str) -> String {
    if !source.contains("![") {
        return source.to_owned();
    }
    let Ok(root) = markdown::to_mdast(source, &ParseOptions::gfm()) else {
        return source.to_owned();
    };
    let mut definitions = HashMap::new();
    collect_definitions(&root, &mut definitions);
    let mut replacements = Vec::new();
    collect_images(&root, &definitions, false, &mut replacements);

    let mut result = String::with_capacity(source.len());
    let mut cursor = 0;
    for (range, replacement) in replacements {
        result.push_str(&source[cursor..range.start]);
        result.push_str(&replacement);
        cursor = range.end;
    }
    result.push_str(&source[cursor..]);
    result
}

fn collect_definitions<'a>(node: &'a Node, definitions: &mut HashMap<&'a str, &'a str>) {
    if let Node::Definition(definition) = node {
        definitions
            .entry(&definition.identifier)
            .or_insert(&definition.url);
    }
    if let Some(children) = node.children() {
        for child in children {
            collect_definitions(child, definitions);
        }
    }
}

fn collect_images(
    node: &Node,
    definitions: &HashMap<&str, &str>,
    in_link: bool,
    replacements: &mut Vec<(std::ops::Range<usize>, String)>,
) {
    let image = match node {
        Node::Image(image) => Some((image.alt.as_str(), image.url.as_str())),
        Node::ImageReference(image) => definitions
            .get(image.identifier.as_str())
            .map(|url| (image.alt.as_str(), *url)),
        _ => None,
    };
    if let Some((alt, url)) = image {
        let label = if alt.is_empty() {
            format!("图片：{url}")
        } else {
            format!("图片：{alt}（{url}）")
        };
        let label = escape(&label);
        // 链接内不能嵌套链接，保留外层目标并将图片目标放进可见文字。
        let replacement = if in_link {
            label
        } else {
            format!("[{label}](<{}>)", escape(url))
        };
        if let Some(position) = node.position() {
            replacements.push((position.start.offset..position.end.offset, replacement));
        }
    }
    if let Some(children) = node.children() {
        let in_link = in_link || matches!(node, Node::Link(_) | Node::LinkReference(_));
        for child in children {
            collect_images(child, definitions, in_link, replacements);
        }
    }
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii_punctuation() {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered_parts(node: &Node, text: &mut String, links: &mut Vec<String>) {
        match node {
            Node::Text(node) => text.push_str(&node.value),
            Node::Link(node) => links.push(node.url.clone()),
            Node::Image(_) | Node::ImageReference(_) => panic!("image was not replaced"),
            _ => {}
        }
        if let Some(children) = node.children() {
            for child in children {
                rendered_parts(child, text, links);
            }
        }
    }

    #[test]
    fn images_keep_readable_labels_and_destinations() {
        let source = "前文 ![示意图](https://example.com/a.png)\n\n\
            ![引用][Picture] ![picture][] ![picture]\n\n\
            ![](/tmp/empty.png) ![本地](</tmp/my photo(1).png>)\n\n\
            ![方括号\\[x\\] &amp; 星号*](https://example.com/a.png?a=1&b=2)\n\n\
            [picture]: /tmp/reference.png\n";
        let result = images_as_links(source);
        let root = markdown::to_mdast(&result, &ParseOptions::gfm()).unwrap();
        let (mut text, mut links) = (String::new(), Vec::new());
        rendered_parts(&root, &mut text, &mut links);
        for label in [
            "图片：示意图（https://example.com/a.png）",
            "图片：引用（/tmp/reference.png）",
            "图片：picture（/tmp/reference.png）",
            "图片：/tmp/empty.png",
            "图片：本地（/tmp/my photo(1).png）",
            "图片：方括号[x] & 星号*（https://example.com/a.png?a=1&b=2）",
        ] {
            assert!(text.contains(label), "missing {label:?} from {text:?}");
        }
        assert_eq!(
            links,
            [
                "https://example.com/a.png",
                "/tmp/reference.png",
                "/tmp/reference.png",
                "/tmp/reference.png",
                "/tmp/empty.png",
                "/tmp/my photo(1).png",
                "https://example.com/a.png?a=1&b=2",
            ]
        );
    }

    #[test]
    fn code_escaped_images_and_ordinary_markdown_are_unchanged() {
        let source = "# 标题\n\n**正文** [普通链接](https://example.com)\n\n\
            `![行内代码](a.png)`\n\n```markdown\n![围栏](b.png)\n```\n\n\
            \\![转义](c.png) ![未定义][missing]\n";
        assert_eq!(images_as_links(source), source);
    }

    #[test]
    fn linked_images_preserve_the_outer_link() {
        let source = "[![截图](/tmp/screen.png)](https://example.com/page)\n\n\
            [![引用][image]][page]\n\n[image]: /tmp/ref.png\n\n[page]: /page\n";
        let result = images_as_links(source);
        let root = markdown::to_mdast(&result, &ParseOptions::gfm()).unwrap();
        let (mut text, mut links) = (String::new(), Vec::new());
        rendered_parts(&root, &mut text, &mut links);
        assert!(text.contains("图片：截图（/tmp/screen.png）"));
        assert!(text.contains("图片：引用（/tmp/ref.png）"));
        assert_eq!(links, ["https://example.com/page"]);
        assert!(result.contains("][page]"));
    }
}
