import i18n from "i18next";
import { initReactI18next, useTranslation } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import zh from "./zh";
import en from "./en";

export function useI18n(namespace?: string) {
  const { t } = useTranslation();
  if (namespace) {
    return (key: string) => {
      return t(`${namespace}.${key}`);
    };
  }
  return (key: string) => t(key);
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    interpolation: {
      escapeValue: false,
    },
    resources: {
      en: {
        translation: en,
      },
      zh: {
        translation: zh,
      },
    },
  });

export default i18n;
