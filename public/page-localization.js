import { languages, languageTag, translateText } from './translations.js';

const languageSelect = document.querySelector('#language-select');
const storedLanguage = localStorage.getItem('kriptal-language');
let language = languages.some(({ code }) => code === storedLanguage) ? storedLanguage : 'en';
const originalText = new WeakMap();
const originalAttributes = new WeakMap();
const originalTitle = document.title;

function localizePage() {
  document.documentElement.lang = languageTag(language);
  languageSelect.value = language;

  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    if (!originalText.has(node)) originalText.set(node, node.nodeValue);
    const source = originalText.get(node);
    const trimmed = source.trim();
    if (!trimmed) continue;
    const translated = translateText(trimmed, language);
    node.nodeValue = translated === trimmed ? source : source.replace(trimmed, translated);
  }

  document.body.querySelectorAll('[aria-label], [title]').forEach((element) => {
    if (!originalAttributes.has(element)) originalAttributes.set(element, {});
    const sources = originalAttributes.get(element);
    for (const attribute of ['aria-label', 'title']) {
      const value = element.getAttribute(attribute);
      if (value) {
        if (!(attribute in sources)) sources[attribute] = value;
        element.setAttribute(attribute, translateText(sources[attribute], language));
      }
    }
  });

  const pageTitle = document.querySelector('title');
  if (pageTitle) pageTitle.textContent = translateText(originalTitle, language);
}

languageSelect.addEventListener('change', () => {
  language = languageSelect.value;
  localStorage.setItem('kriptal-language', language);
  localizePage();
});

localizePage();
