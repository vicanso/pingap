import i18n from "i18next";
import type { TOptions } from "i18next";
import { initReactI18next, useTranslation } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import zh from "./zh";
import en from "./en";

// `options` is passed through so callers can interpolate, e.g. t("summary", { count }).
export function useI18n(namespace?: string) {
  const { t } = useTranslation();
  if (namespace) {
    return (key: string, options?: TOptions) => {
      return t(`${namespace}.${key}`, options);
    };
  }
  return (key: string, options?: TOptions) => t(key, options);
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
