import React from "react";
import { useLocation } from "react-router-dom";

import Header from "./../Header/Header";
import Routers from "../../router/Routers";
import Footer from "./../Footer/Footer";
import { LanguageProvider } from "../../context/LanguageContext";

const Layout = () => {
  const location = useLocation();
  const lang = location.pathname.startsWith("/es") ? "es" : "en";

  return (
    <LanguageProvider lang={lang}>
      <Header />
      <Routers />
      <Footer />
    </LanguageProvider>
  );
};
export default Layout;
