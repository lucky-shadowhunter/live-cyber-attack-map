const express = require("express");
const cors = require("cors");
const path = require("path");
const https = require("https");
const WebSocket = require("ws");
const axios = require("axios");
const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS for frontend requests
app.use(cors());

// Start Express HTTP    server
const server = app.listen(PORT, () => console.log(`HTTP Server running at http://localhost:${PORT}`));

// Create a WebSocket server
const wss = new WebSocket.Server({ server });


app.get("/trends/:countryCode", async (req, res) => {
    const countryCode = req.params.countryCode ? req.params.countryCode.toUpperCase() : "";
    try {
        const response = await axios.get(`https://threatmap-api.checkpoint.com/ThreatMap/api/countries/${countryCode}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch country trends" });
    }
});

app.get("/getTopOrigins", async (req, res) => {
    try {
        const response = await axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin', {
            headers: {
                'Authorization': 'Bearer c7yWU9Q5KXm72xUKX0anKYLbc3q8f9yWsTqN1eNa',
                'Content-Type': 'application/json'
            },
            params: {
                dateRange: '7d'  // Example: Use range to specify the time period
            }
        })
        res.json(response.data.result.top_0);
    } catch (error) {
        console.error('Error details:', error.response?.data || error.message);
        res.status(500).json({ 
            error: "Failed to fetch topStats",
            details: error.response?.data || error.message
        });
    }
})

app.get("/getTopDestinations", async (req, res) => {
    try {
        const response = await axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target', {
            headers: {
                'Authorization': 'Bearer c7yWU9Q5KXm72xUKX0anKYLbc3q8f9yWsTqN1eNa',
                'Content-Type': 'application/json'
            },
            params: {
                dateRange: '7d'  // Example: Use range to specify the time period
            }
        })
        res.json(response.data.result.top_0);
    } catch (error) {
        console.error('Error details:', error.response?.data || error.message);
        res.status(500).json({ 
            error: "Failed to fetch topStats",
            details: error.response?.data || error.message
        });
    }
})

app.get("/getTopIndustry", async (req, res) => {
    try {
        const response = await axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/industry', {
            headers: {
                'Authorization': 'Bearer c7yWU9Q5KXm72xUKX0anKYLbc3q8f9yWsTqN1eNa',
                'Content-Type': 'application/json'
            },
            params: {
                dateRange: '7d'  // Example: Use range to specify the time period
            }
        })
        res.json(response.data.result.top_0);
    } catch (error) {
        console.error('Error details:', error.response?.data || error.message);
        res.status(500).json({ 
            error: "Failed to fetch topStats",
            details: error.response?.data || error.message
        });
    }
})


app.get("/getAttackRate", async (req, res) => {
    try {
        // Make all API calls simultaneously using Promise.all
        const [methodResponse, httpResponse, ipResponse, mitigationResponse] = await Promise.all([
            axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer7/summary/http_method', {
                headers: {
                    'Authorization': 'Bearer c7yWU9Q5KXm72xUKX0anKYLbc3q8f9yWsTqN1eNa',
                    'Content-Type': 'application/json'
                },
                params: {
                    dateRange: '7d'
                }
            }),
            axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer7/summary/http_version', {
                headers: {
                    'Authorization': 'Bearer c7yWU9Q5KXm72xUKX0anKYLbc3q8f9yWsTqN1eNa',
                    'Content-Type': 'application/json'
                },
                params: {
                    dateRange: '7d'
                }
            }),
            axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer7/summary/ip_version', {
                headers: {
                    'Authorization': 'Bearer c7yWU9Q5KXm72xUKX0anKYLbc3q8f9yWsTqN1eNa',
                    'Content-Type': 'application/json'
                },
                params: {
                    dateRange: '7d'
                }
            }),
            axios.get('https://api.cloudflare.com/client/v4/radar/attacks/layer7/summary/mitigation_product', {
                headers: {
                    'Authorization': 'Bearer c7yWU9Q5KXm72xUKX0anKYLbc3q8f9yWsTqN1eNa',
                    'Content-Type': 'application/json'
                },
                params: {
                    dateRange: '7d'
                }
            })
        ]);

        // Extract data from responses
        const {GET, POST} = methodResponse.data.result.summary_0;
        const HTTP = httpResponse.data.result.summary_0;
        const {IPv4, IPv6} = ipResponse.data.result.summary_0;
        const {DDOS, WAF} = mitigationResponse.data.result.summary_0;

        res.json({GET, POST, HTTP, IPv4, IPv6, DDOS, WAF});

    } catch (error) {
        console.error('Error details:', error.response?.data || error.message);
        res.status(500).json({ 
            error: "Failed to fetch topStats",
            details: error.response?.data || error.message
        });
    }
})

async function fetchAttackData() {
    const response = await axios.get(`https://ltm-prod-api.radware.com/map/attacks?limit=10`);
    return response.data;
}


// Handle WebSocket connections
wss.on("connection", async (ws) => {
    console.log("New WebSocket client connected");
    
    // Send initial data immediately when client connects
    try {
        const initialData = await fetchAttackData();
        ws.send(JSON.stringify(initialData));
    } catch (error) {
        console.error("Error fetching initial attack data:", error.response.data.errors);
    }
    
    // Set up interval for this specific connection
    const intervalId = setInterval(async () => {
        try {
            const attackData = await fetchAttackData();
            // Only send to this specific client if it's still connected
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(attackData));
            }
        } catch (error) {
            console.error("Error fetching attack data:", error);
        }
    }, 10000); 

    ws.on("close", () => {
        console.log("WebSocket client disconnected.");
        clearInterval(intervalId);
    });
});


app.use(express.static(path.join(__dirname, 'src')));
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
})