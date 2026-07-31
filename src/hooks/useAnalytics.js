import { useEffect } from "react";
import { useLocation } from "react-router-dom";

// GA4 no recarga la página en una SPA, así que gtag('config', ...) con
// send_page_view:false (ver public/index.html) no manda nada solo; hay que
// disparar el evento page_view a mano cada vez que cambia la ruta.
// Se ignora localhost para no ensuciar los datos reales con pruebas locales.
const useAnalytics = () => {
  const location = useLocation();

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.gtag !== "function") return;
    if (window.location.hostname === "localhost") return;

    // Helmet actualiza el <title> después del render; se espera un tick
    // para que el page_view reporte el título correcto de la página nueva.
    const timeoutId = setTimeout(() => {
      window.gtag("event", "page_view", {
        page_path: location.pathname + location.search,
        page_location: window.location.href,
        page_title: document.title,
      });
    }, 50);

    return () => clearTimeout(timeoutId);
  }, [location]);
};

export default useAnalytics;
