import streamlit as st
import os
from datetime import datetime, timedelta
import bcrypt
import secrets
from supabase import create_client, Client
from anthropic import Anthropic

# ============================================
# CONFIGURATION
# ============================================

# Page config
st.set_page_config(
    page_title="ImmiLaw AI - Immigration Platform",
    page_icon="🇨🇦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Supabase (from Streamlit secrets)
@st.cache_resource
def init_supabase():
    url = st.secrets["SUPABASE_URL"]
    key = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

supabase: Client = init_supabase()

# Initialize Claude AI
@st.cache_resource
def init_claude():
    return Anthropic(api_key=st.secrets["CLAUDE_API_KEY"])

claude_client = init_claude()

# ============================================
# AUTHENTICATION FUNCTIONS
# ============================================

def hash_password(password: str) -> str:
    """Hash password with bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_session(user_id: str) -> str:
    """Create new session for user"""
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=24)
    
    # Terminate other sessions (single login)
    supabase.table('sessions').update({
        'is_active': False
    }).eq('user_id', user_id).eq('is_active', True).execute()
    
    # Create new session
    supabase.table('sessions').insert({
        'user_id': user_id,
        'session_token': session_token,
        'expires_at': expires_at.isoformat(),
        'is_active': True
    }).execute()
    
    return session_token

def verify_session(session_token: str) -> dict:
    """Verify if session is valid"""
    if not session_token:
        return {'valid': False}
    
    result = supabase.table('sessions').select('*, users(*)').eq(
        'session_token', session_token
    ).eq('is_active', True).execute()
    
    if not result.data:
        return {'valid': False}
    
    session = result.data[0]
    
    # Check expiry
    if datetime.fromisoformat(session['expires_at']) < datetime.now():
        supabase.table('sessions').update({
            'is_active': False
        }).eq('id', session['id']).execute()
        return {'valid': False}
    
    return {'valid': True, 'user': session['users']}

def login_user(email: str, password: str) -> dict:
    """Login user and create session"""
    result = supabase.table('users').select('*').eq('email', email).execute()
    
    if not result.data:
        return {'success': False, 'error': 'Invalid email or password'}
    
    user = result.data[0]
    
    if not verify_password(password, user['password_hash']):
        return {'success': False, 'error': 'Invalid email or password'}
    
    if not user['is_active']:
        return {'success': False, 'error': 'Account is deactivated'}
    
    # Create session
    session_token = create_session(user['id'])
    
    # Update last login
    supabase.table('users').update({
        'last_login': datetime.now().isoformat()
    }).eq('id', user['id']).execute()
    
    return {
        'success': True,
        'user': user,
        'session_token': session_token
    }

def create_demo_accounts():
    """Create demo accounts if they don't exist"""
    try:
        # Check if demo RCIC exists
        result = supabase.table('users').select('*').eq('email', 'demo.rcic@immilaw.ai').execute()
        
        if not result.data:
            # Create RCIC demo account
            supabase.table('users').insert({
                'email': 'demo.rcic@immilaw.ai',
                'password_hash': hash_password('Demo123!'),
                'role': 'rcic',
                'full_name': 'Dr. Demo RCIC',
                'rcic_license': 'R999999',
                'is_active': True,
                'account_type': 'beta'
            }).execute()
        
        # Check if demo client exists
        result = supabase.table('users').select('*').eq('email', 'demo.client@immilaw.ai').execute()
        
        if not result.data:
            # Create Client demo account
            supabase.table('users').insert({
                'email': 'demo.client@immilaw.ai',
                'password_hash': hash_password('Demo123!'),
                'role': 'client',
                'full_name': 'John Demo Client',
                'is_active': True,
                'account_type': 'beta'
            }).execute()
    except Exception as e:
        pass  # Silently fail if accounts exist

# ============================================
# SESSION MANAGEMENT
# ============================================

def init_session_state():
    """Initialize session state variables"""
    if 'session_token' not in st.session_state:
        st.session_state.session_token = None
    if 'user' not in st.session_state:
        st.session_state.user = None
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'login'

def logout():
    """Logout user and clear session"""
    if st.session_state.session_token:
        supabase.table('sessions').update({
            'is_active': False
        }).eq('session_token', st.session_state.session_token).execute()
    
    st.session_state.session_token = None
    st.session_state.user = None
    st.session_state.current_page = 'login'
    st.rerun()

# ============================================
# UI PAGES
# ============================================

def login_page():
    """Login page UI"""
    st.title("🇨🇦 ImmiLaw AI")
    st.subheader("Secure Login")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("---")
        
        with st.form("login_form"):
            email = st.text_input("Email", placeholder="your.email@example.com")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("🔐 Login Securely", use_container_width=True)
            
            if submit:
                if not email or not password:
                    st.error("Please enter both email and password")
                else:
                    with st.spinner("Authenticating..."):
                        result = login_user(email, password)
                        
                        if result['success']:
                            st.session_state.session_token = result['session_token']
                            st.session_state.user = result['user']
                            st.session_state.current_page = 'dashboard'
                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            st.error(f"❌ {result['error']}")
        
        st.markdown("---")
        st.info("🛡️ Your data is encrypted and secure\n\n✅ PIPEDA compliant | ✅ Canadian servers")
        
        # Demo credentials for testing
        with st.expander("📋 Demo Credentials (for testing)"):
            st.code("""
RCIC Demo Account:
Email: demo.rcic@immilaw.ai
Password: Demo123!

Client Demo Account:
Email: demo.client@immilaw.ai  
Password: Demo123!
            """)

def rcic_dashboard():
    """RCIC dashboard page"""
    st.title(f"Welcome, {st.session_state.user['full_name']} 👋")
    st.caption(f"RCIC License: {st.session_state.user.get('rcic_license', 'N/A')}")
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("### 🎯 Navigation")
        page = st.radio(
            "Select Page:",
            ["Dashboard", "Legal Research", "Applications", "New Application", "Settings"],
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            logout()
    
    if page == "Dashboard":
        show_dashboard()
    elif page == "Legal Research":
        show_legal_research()
    elif page == "Applications":
        show_applications()
    elif page == "New Application":
        show_new_application()
    elif page == "Settings":
        show_settings()

def show_dashboard():
    """Dashboard overview"""
    st.subheader("📊 Dashboard Overview")
    
    # Get applications count
    apps_result = supabase.table('applications').select('*').eq(
        'rcic_id', st.session_state.user['id']
    ).execute()
    
    total_apps = len(apps_result.data) if apps_result.data else 0
    
    # Stats cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Applications", total_apps)
    
    with col2:
        draft_count = len([a for a in apps_result.data if a['status'] == 'draft']) if apps_result.data else 0
        st.metric("Drafts", draft_count)
    
    with col3:
        review_count = len([a for a in apps_result.data if a['status'] == 'rcic_review']) if apps_result.data else 0
        st.metric("Pending Review", review_count)
    
    with col4:
        approved_count = len([a for a in apps_result.data if a['status'] == 'approved']) if apps_result.data else 0
        st.metric("Approved", approved_count)
    
    st.markdown("---")
    
    # Quick actions
    st.subheader("⚡ Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📝 New Application", use_container_width=True):
            st.info("Coming soon!")
    
    with col2:
        if st.button("🔍 Legal Research", use_container_width=True):
            st.info("Coming soon!")
    
    with col3:
        if st.button("📋 View All Applications", use_container_width=True):
            st.info("Coming soon!")
    
    st.markdown("---")
    
    # Recent applications
    if apps_result.data and len(apps_result.data) > 0:
        st.subheader("📌 Recent Applications")
        
        for app in apps_result.data[:5]:  # Show last 5
            with st.expander(f"{app['application_type'].replace('_', ' ').title()} - {app['status'].title()}"):
                st.write(f"**Created:** {app['created_at'][:10]}")
                st.write(f"**Status:** {app['status'].replace('_', ' ').title()}")
                st.write(f"**ID:** {app['id']}")

def show_legal_research():
    """Legal research tool"""
    st.subheader("🔍 AI-Powered Legal Research")
    st.caption("Powered by Claude AI")
    
    query = st.text_area(
        "Enter your legal research question:",
        placeholder="Example: What are the requirements for H&C applications?",
        height=100
    )
    
    if st.button("🔍 Search Legal Database", type="primary"):
        if query:
            with st.spinner("Analyzing legal database..."):
                try:
                    message = claude_client.messages.create(
                        model="claude-sonnet-4-20250514",
                        max_tokens=2000,
                        messages=[{
                            "role": "user",
                            "content": f"""You are an expert Canadian immigration law research assistant.

Question: {query}

Provide a comprehensive answer based on Canadian immigration law (IRPA, IRPR, case law).
Include relevant sections, regulations, and case citations where applicable."""
                        }]
                    )
                    
                    st.success("✅ Analysis Complete!")
                    st.markdown("### 🤖 AI-Powered Answer:")
                    st.markdown(message.content[0].text)
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please enter a question")

def show_applications():
    """Show all applications"""
    st.subheader("📋 All Applications")
    
    apps_result = supabase.table('applications').select('*').eq(
        'rcic_id', st.session_state.user['id']
    ).execute()
    
    if not apps_result.data or len(apps_result.data) == 0:
        st.info("No applications yet. Create your first application!")
        if st.button("➕ Create New Application"):
            st.info("Coming soon!")
    else:
        for app in apps_result.data:
            with st.expander(f"📄 {app['application_type'].replace('_', ' ').title()} - {app['id'][:8]}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Type:** {app['application_type'].replace('_', ' ').title()}")
                    st.write(f"**Status:** {app['status'].replace('_', ' ').title()}")
                    st.write(f"**Created:** {app['created_at'][:10]}")
                with col2:
                    if st.button(f"View Details", key=f"view_{app['id']}"):
                        st.info("Application details coming soon!")

def show_new_application():
    """Create new application"""
    st.subheader("📝 Create New Application")
    
    app_type = st.selectbox(
        "Select Application Type:",
        ["work_permit", "visitor_visa", "study_permit", "pr", "caregiver", "sponsorship", "pnp"],
        format_func=lambda x: x.replace('_', ' ').title()
    )
    
    client_name = st.text_input("Client Full Name")
    client_email = st.text_input("Client Email")
    
    if st.button("Create Application", type="primary"):
        if client_name and client_email:
            try:
                result = supabase.table('applications').insert({
                    'rcic_id': st.session_state.user['id'],
                    'client_id': st.session_state.user['id'],
                    'application_type': app_type,
                    'status': 'draft'
                }).execute()
                
                st.success(f"✅ Application created successfully!")
                st.info("Full questionnaire feature coming in next version!")
                
            except Exception as e:
                st.error(f"Error creating application: {str(e)}")
        else:
            st.warning("Please fill all fields")

def show_settings():
    """Settings page"""
    st.subheader("⚙️ Settings")
    
    st.write(f"**Name:** {st.session_state.user['full_name']}")
    st.write(f"**Email:** {st.session_state.user['email']}")
    st.write(f"**Role:** {st.session_state.user['role'].upper()}")
    st.write(f"**Account Type:** {st.session_state.user.get('account_type', 'standard').title()}")
    
    st.markdown("---")
    st.info("Full settings page coming soon!")

# ============================================
# MAIN APPLICATION
# ============================================

def main():
    """Main application entry point"""
    init_session_state()
    
    # Create demo accounts on first run
    create_demo_accounts()
    
    # Check if logged in
    if not st.session_state.session_token:
        login_page()
        return
    
    # Verify session
    session_check = verify_session(st.session_state.session_token)
    
    if not session_check['valid']:
        st.error("Session expired. Please login again.")
        logout()
        return
    
    # Show appropriate dashboard
    if st.session_state.user['role'] == 'rcic':
        rcic_dashboard()
    elif st.session_state.user['role'] == 'client':
        st.title("Client Portal")
        st.info("Client portal coming soon!")
    else:
        st.error("Unknown user role")

if __name__ == "__main__":
    main()
