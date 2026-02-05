
import { GoogleGenAI, Type } from "@google/genai";
import { Packet, AttackType } from "../types";

export const analyzeTrafficWithAI = async (packets: Packet[]): Promise<{
  attackType: AttackType;
  confidence: number;
  reason: string;
}> => {
  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
  
  const trafficSample = packets.slice(-10).map(p => ({
    src: p.sourceIp,
    dst: p.destIp,
    proto: p.protocol,
    length: p.length
  }));

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: `Analysez ce trafic réseau pour détecter des cyberattaques. Types autorisés : SYN Flood, Port Scan, ARP Spoofing, UDP Flood, Normal.
      Trafic : ${JSON.stringify(trafficSample)}`,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            attackType: { type: Type.STRING, description: "Un de : SYN Flood, Port Scan, ARP Spoofing, UDP Flood, Normal" },
            confidence: { type: Type.NUMBER },
            reason: { type: Type.STRING }
          },
          required: ["attackType", "confidence", "reason"]
        }
      }
    });

    const jsonStr = response.text?.trim() || "{}";
    return JSON.parse(jsonStr);
  } catch (error) {
    console.error("Erreur IA:", error);
    return {
      attackType: AttackType.NORMAL,
      confidence: 0,
      reason: "Échec de l'analyse"
    };
  }
};
