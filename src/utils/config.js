export const BASE_URL = 'https://cloud-pe.com/tour';
export const IMAGE_BASE_URL = 'https://cloud-pe.com/public';

// Endpoints específicos para mayor claridad
export const API_ENDPOINTS = {
  getAllTours: (page = 0) => `${BASE_URL}/getAllTours?page=${page}`,
  getTotalTours: () => `${BASE_URL}/getTotalTours`,
  getTour: (id) => `${BASE_URL}/get?id=${id}`,
  addReview: (id) => `${BASE_URL}/review?id=${id}`,
  searchTours: (city, distance, maxGroupSize) => 
    `${BASE_URL}/search?city=${city}&distance=${distance}&maxGroupSize=${maxGroupSize}`
};