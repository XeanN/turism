import React, { createContext, useContext } from "react";

const LanguageContext = createContext("en");

// El idioma se decide por la URL (/es/... vs sin prefijo), no por estado
// local ni localStorage: así cada versión es una URL indexable aparte,
// que es lo que Google espera de un sitio bilingüe (hreflang).
export const LanguageProvider = ({ lang, children }) => (
  <LanguageContext.Provider value={lang}>{children}</LanguageContext.Provider>
);

export const useLanguage = () => useContext(LanguageContext);

// Antepone /es a un path interno cuando corresponde, para armar links que
// respeten el idioma actual (ej: dentro del Header, TourCard, etc.)
export const withLang = (path, lang) =>
  lang === "es" ? `/es${path === "/" ? "" : path}` : path;
