import axios from 'axios'

const BASE = '/api'

const api = axios.create({
  baseURL: BASE,
  timeout: 120000,
  headers: { 'Content-Type': 'application/json' },
})

// Alerts
export const getAlerts = (params = {}) => api.get('/alerts', { params })
export const getAlert  = (id)         => api.get(`/alerts/${id}`)
export const postAction = (id, body)  => api.post(`/alerts/${id}/action`, body)

// Analysis
export const analyzeEvent = (event)   => api.post('/analyze', { event })

// Incidents
export const getIncidents = ()        => api.get('/incidents')

// Reports
export const getReport = (incidentId) => api.get(`/reports/${incidentId}`)

// Stats
export const getStats = ()            => api.get('/stats')

// Health
export const getHealth = ()           => axios.get('/health')

export default api
