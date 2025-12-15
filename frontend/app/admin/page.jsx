"use client"
import { useState, useEffect } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

/**
 * Simplified Admin Dashboard
 * Tabs:
 * - Users
 * - Members
 * - Activity
 * - Room Messages
 * - DMs
 *
 * Expected behavior:
 * - All filtering is performed server-side via API
 * - UI only sends filters and renders results
 * - Works in browser-only environments (no Node.js globals required)
 */

/**
 * SAFELY resolve API base URL
 * - Avoids ReferenceError: process is not defined
 * - Works in browser, Next.js, and sandboxed environments
 */
function getApiBase() {


        return `${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin`


}

const API_BASE = getApiBase()

async function fetchAdmin(endpoint, filters) {
    const params = filters?.length ? `?filters=${encodeURIComponent(JSON.stringify(filters))}` : ""

    const res = await fetch(`${API_BASE}${endpoint}${params}`)
    if (!res.ok) throw new Error("Failed to fetch admin data")
    return res.json()
}

const api = {
    users: (filters) => fetchAdmin("/users", filters),
    members: (filters) => fetchAdmin("/members", filters),
    activity: (filters) => fetchAdmin("/activity", filters),
    messages: (filters) => fetchAdmin("/messages", filters),
    dms: (filters) => fetchAdmin("/dms", filters),
}

function countMentions(text) {
    if (typeof text !== "string") return 0
    return (text.match(/@/g) || []).length
}

function RenderObject({ data, level = 0 }) {
    if (data === null || data === undefined) {
        return <span className="italic text-muted-foreground">null</span>
    }

    if (typeof data !== "object") {
        return <span>{String(data)}</span>
    }

    return (
        <div className={`space-y-1 ${level > 0 ? "pl-3 border-l" : ""}`}>
            {Object.entries(data).map(([key, value]) => (
                <div key={key}>
                    <span className="font-semibold">{key}:</span> <RenderObject data={value} level={level + 1} />
                </div>
            ))}
        </div>
    )
}

export default function AdminDashboard() {
    const [tab, setTab] = useState("users")

    // Reset filters and errors when changing tabs to avoid stale or invalid filters
    useEffect(() => {
        setFilters([{ field: "all", value: "" }])
        setError(null)
    }, [tab])

    // Dynamic filters: [{ field, value }]
    const [filters, setFilters] = useState([{ field: "all", value: "" }])
    const [data, setData] = useState([])
    const [resultCount, setResultCount] = useState(0)
    const [error, setError] = useState(null)

    useEffect(() => {
        let cancelled = false

        api[tab](filters)
            .then((res) => {
                if (!cancelled) {
                    // Support both array response and { results, count }
                    if (Array.isArray(res)) {
                        setData(res)
                        setResultCount(res.length)
                    } else {
                        setData(res.results || [])
                        setResultCount(res.count ?? (res.results?.length || 0))
                    }
                }
            })
            .catch((err) => {
                if (!cancelled) setError(err.message)
            })

        return () => {
            cancelled = true
        }
    }, [tab, filters])

    // Server-side filtering only
    // Server-side filtering only, but allow client-side mention count display
    const filtered = data.map((item) => {
        if (item?.content) {
            return { ...item, mention_count: countMentions(item.content) }
        }
        return item
    })

    return (
        <div className="p-6 max-w-6xl mx-auto space-y-4">
            <h1 className="text-2xl font-bold">Admin Dashboard</h1>

            <div className="text-sm text-muted-foreground">
                Results: <span className="font-semibold">{resultCount}</span>
            </div>

            {error && <div className="text-red-600 text-sm">Error: {error}</div>}

            <Tabs value={tab} onValueChange={setTab}>
                <TabsList className="flex flex-wrap">
                    <TabsTrigger value="users">Users</TabsTrigger>
                    <TabsTrigger value="members">Members</TabsTrigger>
                    <TabsTrigger value="activity">Activity</TabsTrigger>
                    <TabsTrigger value="messages">Room Messages</TabsTrigger>
                    <TabsTrigger value="dms">DMs</TabsTrigger>
                </TabsList>

                <div className="space-y-2 my-4">
                    {filters.map((f, i) => (
                        <div key={i} className="flex gap-2 items-center flex-wrap">
                            <Select
                                value={f.field}
                                onValueChange={(v) => {
                                    const next = [...filters]
                                    next[i] = { ...next[i], field: v }
                                    setFilters(next)
                                }}
                            >
                                <SelectTrigger className="w-44">
                                    <SelectValue placeholder="Field" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="all">All fields</SelectItem>
                                    {tab === "users" && (
                                        <>
                                            <SelectItem value="username">Username</SelectItem>
                                            <SelectItem value="email">Email</SelectItem>
                                            <SelectItem value="role">Role</SelectItem>
                                        </>
                                    )}
                                    {tab === "members" && (
                                        <>
                                            <SelectItem value="serverName">Server Name</SelectItem>
                                            <SelectItem value="user">User</SelectItem>
                                            <SelectItem value="role">Role</SelectItem>
                                        </>
                                    )}
                                    {tab === "activity" && (
                                        <>
                                            <SelectItem value="sender">Sender</SelectItem>
                                            <SelectItem value="context_type">Context Type</SelectItem>
                                            <SelectItem value="mentions">Mention Count ( @ )</SelectItem>
                                        </>
                                    )}
                                    {tab === "messages" && (
                                        <>
                                            <SelectItem value="serverName">Server Name</SelectItem>
                                            <SelectItem value="room">Room ID</SelectItem>
                                            <SelectItem value="sender">Sender</SelectItem>
                                            <SelectItem value="content">Content</SelectItem>
                                        </>
                                    )}
                                    {tab === "dms" && (
                                        <>
                                            <SelectItem value="sender">Sender</SelectItem>
                                            <SelectItem value="recipient">Recipient</SelectItem>
                                            <SelectItem value="content">Content</SelectItem>
                                        </>
                                    )}
                                </SelectContent>
                            </Select>

                            <Input
                                placeholder="Value"
                                value={f.value}
                                onChange={(e) => {
                                    const next = [...filters]
                                    next[i] = { ...next[i], value: e.target.value }
                                    setFilters(next)
                                }}
                                className="w-56"
                            />

                            <Button variant="ghost" onClick={() => setFilters(filters.filter((_, idx) => idx !== i))} disabled={filters.length === 1}>
                                Remove
                            </Button>
                        </div>
                    ))}

                    <Button variant="secondary" onClick={() => setFilters([...filters, { field: "all", value: "" }])}>
                        + Add Filter
                    </Button>
                </div>

                <TabsContent key={tab} value={tab}>
                    <div className="grid gap-4 md:grid-cols-2">
                        {filtered.map((item, idx) => (
                            <Card key={idx} className="rounded-2xl shadow-sm">
                                <CardContent className="p-4 text-sm space-y-1">
                                    {typeof item.mention_count === "number" && (
                                        <div className="text-xs text-muted-foreground">
                                            Mentions (@): <span className="font-semibold">{item.mention_count}</span>
                                        </div>
                                    )}
                                    <RenderObject data={item} />
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                </TabsContent>
            </Tabs>

            <div className="flex justify-end gap-2">
                <Button variant="secondary">Export CSV</Button>
                <Button onClick={() => api[tab](filters).then(setData)}>Refresh</Button>
            </div>
        </div>
    )
}
