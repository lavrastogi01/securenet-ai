import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/contexts/AuthContext";
import { LiveDataProvider } from "@/contexts/LiveDataContext";
import ProtectedRoute from "@/components/ProtectedRoute";
import DashboardLayout from "./components/DashboardLayout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import TrafficAnalysis from "./pages/TrafficAnalysis";
import UploadDetect from "./pages/UploadDetect";
import ThreatLogs from "./pages/ThreatLogs";
import ModelSecurity from "./pages/ModelSecurity";
import AdversarialDetection from "./pages/AdversarialDetection";
import ModelIntegrity from "./pages/ModelIntegrity";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <AuthProvider>
        <LiveDataProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route element={<ProtectedRoute><DashboardLayout /></ProtectedRoute>}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/traffic-analysis" element={<TrafficAnalysis />} />
              <Route path="/upload-detect" element={<UploadDetect />} />
              <Route path="/threat-logs" element={<ThreatLogs />} />
              <Route path="/model-security" element={<ModelSecurity />} />
              <Route path="/adversarial-detection" element={<AdversarialDetection />} />
              <Route path="/model-integrity" element={<ModelIntegrity />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
        </LiveDataProvider>
      </AuthProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
