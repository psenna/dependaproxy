import { Link } from 'react-router-dom'

export default function DashboardPage() {
  return (
    <div>
      <h1 className="text-red-500 text-3xl font-bold">DependaProxy</h1>
      <p className="mt-4">
        <Link to="/projects" className="text-blue-500 underline">
          View projects
        </Link>
      </p>
    </div>
  )
}
